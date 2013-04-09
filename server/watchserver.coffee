http = require('http')
fs = require('fs')
crypto = require('crypto')
ursa = require('ursa')
url = require('url')
redis = require('redis')
toml = require('tomljs')
queue = require('./queue')

###
	Redis data structure
	*	password        - JSON(salt, hash)
	*	token:#token    - int(1)
	*	id_salt         - string
	*	peers           - hash(ID ,JSON(user, pubkey))
	*	sortby:index    - zset(ID by index)
	*	sortby:lastping - zset(ID by lastPing)
###

class WatchServer
	constructor: (@config) ->
		@idDB = {}
		@conDB = {}
		@static = {}
		throw "Config missing" if not @config
		@redis = redis.createClient(@config.redis.port, @config.redis.host)
		@redis.auth(@config.redis.password) if @config.redis.password isnt ""
		startup = queue()
		startup.defer((cb) =>
			@redis.on('ready', =>
				@redis.get('id_salt', (err, data) =>
					throw "Error reading from Redis database: #{err}" if err
					if not data
						crypto.randomBytes(@config.saltLength, (err, salt) =>
							throw "Error generating ID salt: #{err}" if err
							@redis.set('id_salt', salt.toString('base64'), (err, data) =>
								throw "Error reading from Redis database: #{err}" if err
								@IDSalt = salt
								cb(false)
							)
						)
					else
						@IDSalt = new Buffer(data, 'base64')
						cb(false)
				)
			)
		, queue.D)
		startup.defer((cb) =>
			fs.readFile('./maintainance.html', (err, data) =>
				throw "Error reading back-end maintainance.html: #{err}" if err
				@maintainance = data
				cb()
			)
		, queue.D)
		for i in fs.readdirSync('./static/')
			startup.defer((cb) =>
				filename = i
				fs.readFile('./static/'+filename, (err, data) =>
					throw "Error reading static file #{filename}: #{err}" if err
					@static[filename] = data
					cb()
				)
			, queue.D)
		startup.await( =>
			@server = http.createServer(@request)
			@server.listen(@config.port)
		)

	valid_base64: /^[\w\+=/]+$/
	MIME:
		'js': 'application/javascript'
		'css': 'text/css'
		'afm': 'application/x-font-afm'
		'ttf': 'application/x-font-ttf'
		'eot': 'application/vnd.ms-fontobject'
		'woff': 'application/font-woff'

	request: (req, res) =>
		###
			Status Codes
			200: OK
			400: malformed request
			403: user names don't match
			404: peer not found
			409: IP sent doesn't match what the server detected
		###
		console.info req.url
		urlInfo = url.parse(req.url, true)
		if urlInfo.pathname[0..7] == '/static/'
			filename = decodeURIComponent(urlInfo.pathname)[8..]
			if not @static[filename]
				res.writeHead(404)
				return res.end()
			extension = filename[filename.lastIndexOf('.')+1..]
			res.writeHead(200,
				'content-type': @MIME[extension]
				'content-length': @static[filename].length
			)
			return res.end(@static[filename])
		switch urlInfo.pathname
			when '/'
				lastPing = Date.now()
				unless urlInfo.query.id and urlInfo.query.content
					res.writeHead(400)
					return res.end()
				@decryptPulse(urlInfo.query.id, urlInfo.query.content, (errCode, pubkey, message) =>
					if errCode
						res.writeHead(errCode)
					else if message.peer
						if(@conDB[message.peer])
							data = Object.create(@conDB[message.peer])
							delete data.pubkey
							response = @pubkey.publicEncrypt JSON.stringify(data), 'utf8', 'base64'
							res.writeHead(200)
							return res.end(response)
						else
							res.writeHead(404)
					else
						detectedIP = if @config.IPheader then req.headers[@config.IPheader] else req.connection.remoteAddress
						if detectedIP isnt message.ip
							res.writeHead(409)
						else
							res.writeHead(200)
						@conDB[message.user] = message
						@conDB[message.user].pubkey = pubkey
						@conDB[message.user].lastPing = lastPing
						@redis.zadd('sortby:lastping', lastPing, urlInfo.query.id)
					res.end()
				)
			when '/maintainance'
				res.writeHead(200,
					'content-type': "text/html"
					'content-length': @maintainance.length
				)
				res.end(@maintainance)
			when '/ajax/auth'
				if urlInfo.query.password
					@redis.get("password", (err, data) =>
						if err
							console.error("[Redis]Error: ", err)
							res.writeHead(500)
							res.end()
						else if not data
							if urlInfo.query.password is @config.password
								@generateToken((err, token) =>
									if err
										res.writeHead(500)
										res.end()
									else
										res.end(JSON.stringify
											'token': token
											'forceReset': true
										)
								)
							else
								res.writeHead(403)
								res.end()
						else
							auth = JSON.parse(data)
							@generateHash(urlInfo.query.password, auth.salt, (err, key) =>
								if err
									res.writeHead(500)
									res.end()
								else if key is auth.hash
									@generateToken((err, token) =>
										if err
											res.writeHead(500)
											res.end()
										else
											res.end(JSON.stringify
												'token': token
											)
									)
								else
									res.writeHead(403)
									res.end()
							)
					)
				else if urlInfo.query.token
					@checkToken(urlInfo.query.token, (err, state) =>
						if err
							res.writeHead(500)
						else if state is true
							res.writeHead(200)
						else
							res.writeHead(403)
						res.end()
					)
				else
					res.writeHead(400)
					res.end()
			when '/ajax/list'
				@checkToken(urlInfo.query.token, (err, state) =>
					if err
						res.writeHead(500)
						return res.end()
					else if state is false
						res.writeHead(403)
						return res.end()
					page = parseInt(urlInfo.query.page) or 0
					@redis.zrange("sortby:index", page*@config.pageSize, (page+1)*@config.pageSize, (err, list) =>
						if err
							console.error("[Redis]Error: ", err)
							res.writeHead(500)
							res.end()
						else if list.length is 0
							res.writeHead(200)
							res.end('[]')
						else
							@redis.hmget('peers', list..., (err, data) =>
								if err
									console.error("[Redis]Error: ", err)
									return res.writeHead(500)
								result = []
								for i in data
									info = JSON.parse(i)
									result.push(@conDB[info.user] or info)
								res.writeHead(200)
								res.end(JSON.stringify(result))
							)
					)
				)

			when '/ajax/add_peer'
				@checkToken(urlInfo.query.token, (err, state) =>
					if err
						res.writeHead(500)
						return res.end()
					else if state is false
						res.writeHead(403)
						return res.end()
					else unless urlInfo.query.name and urlInfo.query.pubkey
						res.writeHead(400)
						return res.end()
					user = decodeURIComponent(urlInfo.query.name)
					queue()
						.defer(@redis.zrevrange.bind(@redis), 'sortby:index', 0, 0, 'withscores', queue.D)
						.defer(@generateID.bind(@), user, queue.D)
						.await((err, data) =>
							if err
								console.err("[Add Peer]Error: ", err)
								res.writeHead(500)
								return res.end()
							currentIndex = if data[0].length isnt 0 then parseInt(data[0][1])+1 else 0
							id = data[1]
							peerInfo =
								'user': user
								# '\n' is escaped as '*'
								'pubkey': decodeURIComponent(urlInfo.query.pubkey).replace(/\*/g, '\n')
							queue()
								.defer(@redis.hset.bind(@redis), 'peers', id, JSON.stringify(peerInfo), queue.D)
								.defer(@redis.zadd.bind(@redis), 'sortby:index', currentIndex, id, queue.D)
								.await((err) =>
									if err
										console.err("[Redis]Error: ", err)
										res.writeHead(500)
									else
										res.writeHead(200)
									res.end()
								)
						)
				)
			when '/ajax/remove_peer'
				@checkToken(urlInfo.query.token, (err, state) =>
					if err
						res.writeHead(500)
						return res.end()
					else if state is false
						res.writeHead(403)
						return res.end()
					else if not urlInfo.query.peer
						res.writeHead(400)
						return res.end()
					@generateID(urlInfo.query.peer, (err, id) =>
						if err
							res.writeHead(500)
							return res.end()
						queue()
							.defer(@redis.hdel.bind(@redis), 'peers', id, queue.D)
							.defer(@redis.zrem.bind(@redis), 'sortby:index', id, queue.D)
							.await((err) =>
								if err
									console.err("[Redis]Error: ", err)
									res.writeHead(500)
								else
									res.writeHead(200)
								res.end()
							)
					)

				)
			when '/ajax/new_password'
				@checkToken(urlInfo.query.token, (err, state) =>
					if err
						res.writeHead(500)
						return res.end()
					else if state is false
						res.writeHead(403)
						return res.end()
					else if not urlInfo.query.password
						res.writeHead(400)
						return res.end()
					else
						crypto.randomBytes(@config.hashLength, (err, salt) =>
							if err
								console.error('[RandomBytes]Error: ', err)
								res.writeHead(500)
								res.end()
							else
								@generateHash(urlInfo.query.password, salt, (err, hash) =>
									if err
										res.writeHead(500)
										res.end()
									auth = 
										'salt': salt.toString('base64')
										'hash': hash.toString('base64')
									@redis.set('password', JSON.stringify(auth), (err) =>
										res.writeHead(200)
										res.end()
									)
								)
						)
				)
	decryptPulse: (id, ciphertext, cb) ->
		if @idDB[id]
			decrypt(@idDB[id])
		else
			@redis.hget("peers", id, (err, data) =>
				if err
					console.error("[Redis]Error: ", err)
					cb(500)
				else
					user = JSON.parse(data)
					@idDB[id] = user
					decrypt(user)
			)
		decrypt = (user) ->
			pubkey = ursa.createPublicKey(user.pubkey, 'utf8')
			message = JSON.parse pubkey.publicDecrypt(ciphertext, 'base64', 'utf8')
			if message.user isnt user.user
				cb(403)
			else
				cb(false, pubkey, message)

	generateToken: (cb) ->
		crypto.randomBytes(@config.tokenLength, (err, tokenBuffer) =>
			if err
				console.error("[RandomBytes]Error: ", err)
				return cb(err)
			token = @toBase64url(tokenBuffer)
			@redis.setex("token:#{token}", @config.tokenTTL, 1, (err) =>
				if err
					console.error("[Redis]Error: ", err)
				else
					cb(false, token)
			)
		)
	generateHash: (content, salt, cb) ->
		crypto.pbkdf2(content, salt, @config.hashIterations, @config.hashLength, (err, hash) =>
			if err
				console.error("[PBKDF2]Error: ", err)
				cb(err)
			else
				cb(false, data.toString('base64'))
		)
	generateID: (user, cb) ->
		crypto.pbkdf2(user, @IDSalt, @config.hashIterations, @config.IDLength, (err, data) =>
			if err
				console.error("[PBKDF2]Error: ", err)
				cb(err)
			else
				cb(false, new Buffer(data).toString('base64'))
		)
	# RFC 4648 base64url encoding
	toBase64url: (buffer) ->
		buffer.toString('base64')
			.replace(/\+/g, '-') # Convert '+' to '-'
			.replace(/\//g, '_') # Convert '/' to '_'
			.replace(/\=+$/, '') # Remove ending '='
	checkToken: (token, cb) ->
		if not token
			cb(false, false)
		@redis.expire("token:#{decodeURIComponent(token)}", @config.tokenTTL, (err, data) =>
			if err
				console.error("[Redis]Error: ", err)
				cb(err)
			else if data is 0
				cb(false, false)
			else
				cb(false, true)
		)



server = new WatchServer toml(fs.readFileSync('config.toml','utf-8'))