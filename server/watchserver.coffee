http = require('http')
https = require('https')
fs = require('fs')
crypto = require('crypto')
ursa = require('ursa')
url = require('url')
redis = require('redis')
toml = require('tomljs')
buffet_lib = require('buffet')
socketIO = require('socket.io')
queue = require('./queue')

###
	Redis data structure
	*	password        - JSON(salt, hash)
	*	token:#token    - int(1)
	*	peers           - hash(ID ,JSON(user, pubkey))
	*	sortby:index    - zset(ID by index)
	*	sortby:lastping - zset(ID by lastPing)
	*	track:peer      - zset(JSON(location) by time)
###

class WatchServer
	constructor: (@config) ->
		@idDB = {} # map of peer info by id
		@conDB = {} # map of connection info by peer name
		throw "Config missing" if not @config
		# setup redis client
		@redis = redis.createClient(@config.redis.port, @config.redis.host)
		@redis.auth(@config.redis.password) if @config.redis.password isnt ""
		# setup static file server
		@buffet = buffet_lib({root: if @config.production is true then './static' else './bootplate'})
		# setup main server
		@server = (if @config.secure is true then https else http).createServer(@peerRequest)
		# setup websocket server
		@wsServer = socketIO.listen(@server).of('/ws')
		if @config.production is true
			@wsServer.set('log level', 1)
			io.enable('browser client minification')
			io.enable('browser client etag')
			io.enable('browser client gzip')
		@wsServer.on('connection', @wsRequest)

		@server.listen(@config.port)

	valid_base64: /^[\w\+=/]+$/

	peerRequest: (req, res) =>
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
		# Why use a routing framework when you only have half a dozen routes?
		switch urlInfo.pathname
			when '/'
				lastPing = Date.now()
				statusCode = 200
				unless urlInfo.query.id and urlInfo.query.content
					if req.headers['user-agent']
						# from browser
						return @buffet(req, res)
					else
						# we don't know what it it from
						statusCode = 400
						return res.end()
				# from watchserver client
				@decryptPulse(urlInfo.query.id, urlInfo.query.content, (errCode, pubkey, message) =>
					if errCode
						statusCode = errCode
					else if message.peer # peer request
						if(@conDB[message.peer])
							data = @shallowClone @conDB[message.peer]
							delete data.pubkey
							response = @conDB[message.peer].pubkey.encrypt JSON.stringify(data), 'utf8'
							res.writeHead(200)
							return res.end(response)
						else
							statusCode = 404
					else # pulse message
						detectedIP = if @config.IPheader then req.headers[@config.IPheader] else req.connection.remoteAddress
						if message.ip?
							if detectedIP isnt message.ip
								statusCode = 409 # conflict ip address
						else
							if message.lan_ip isnt detectedIP
								message.ip ||= detectedIP
							# else
								# sadly, because we and the peer is located in the same
								# lan network, we still don't know the external IP yet
						@conDB[message.user] = message
						@conDB[message.user].pubkey = pubkey
						@conDB[message.user].lastPing = lastPing
						@redis.zadd('sortby:lastping', lastPing, urlInfo.query.id)
					res.writeHead(statusCode)
					res.end()
				)
			else
				@buffet(req, res)

	wsRequest: (con) =>
		con.on('client:auth', @auth)
		con.on('client:update_password', @updatePassword)
		con.on('client:list_peer', @listPeer)
		con.on('client:add_peer', @listPeer)
		con.on('client:remove_peer', @addPeer)
		con.on('client:track_peer', @removePeer)

	auth: (req, cb) =>
		if typeof cb isnt 'function'
			return
		if req.password
			@checkPassword(req.password, (err, validity, isTemp) =>
				if err
					cb(status: 500)
				else if validity is false
					cb(status: 403)
				else
					@generateToken((err, token) =>
						if err
							cb(status: 500)
						else
							cb(
								status: 200
								token: token
								forceReset: isTemp
							)
					)
			)
		else if req.token
			@checkToken(req.token, (err, state) =>
				if err
					cb(status: 500)
				else if state is true
					cb(status: 200)
				else
					cb(status: 403)
			)
		else
			cb(status: 400)

	updatePassword: (req, cb) =>
		if typeof cb isnt 'function'
			return
		if not req.old? and req.new?
			return cb(status: 400)
		oldPassword = req.old
		newPassword = req.new
		@checkToken(req.token, (err, state) =>
			if err
				cb(status: 500)
			else if state is false
				cb(status: 403)
			else
				@checkPassword(oldPassword, (err, validity) =>
					if err
						cb(status: 500)
					else if validity is false
						cb(status: 403)
					else
						crypto.randomBytes(@config.security.saltLength, (err, saltBuffer) =>
							if err
								console.error("[RandomBytes]Error: ", err)
								cb(status: 500)
							else
								salt = saltBuffer.toString('base64')
								@generateHash(newPassword, salt, (err, hash) =>
									if err
										cb(status: 500)
									else
										@redis.set("password",
											JSON.stringify
												salt: salt
												hash: hash
										, (err) =>
											if err
												console.error("[Redis]Error: ", err)
												cb(status: 500)
											else
												cb(status: 200)
										)
								)
						)
				)
		)

	listPeer: (req, cb) =>
		if typeof cb isnt 'function'
			return
		@checkToken(req.token, (err, state) =>
			if err
				return cb(status: 500)
			else if state is false
				return cb(status: 403)
			page = parseInt(req.page) or 0
			@redis.zrange("sortby:index", page*@config.pageSize, (page+1)*@config.pageSize, (err, list) =>
				if err
					console.error("[Redis]Error: ", err)
					cb(status: 500)
				else if list.length is 0
					cb(false, peers: [])
				else
					@redis.hmget('peers', list..., (err, data) =>
						if err
							console.error("[Redis]Error: ", err)
							return cb(status: 500)
						result = []
						tasks = queue()
						for item, index in data
							info = JSON.parse(item)
							if @conDB[info.user]
								peer = @shallowClone @conDB[info.user]
								peer.pubkey = peer.pubkey.toPublicPem('utf8')
								result.push(peer)
							else
								tasks.defer((queue_cb) =>
									peer = info
									@redis.zscore('sortby:lastping', list[index], (err, lastPing) =>
										queue_cb(err) if err
										peer.lastPing = parseInt(lastPing, 10)
										result.push(info)
										queue_cb(false)
									)
								, queue.D)
						tasks.await((err) =>
							if err
								console.error("[Redis]Error: ", err)
								cb(status: 500)
							else
								cb(status: 200, peers: result)
						)
					)
			)
		)

	addPeer: (req, cb) =>
		if typeof cb isnt 'function'
			return
		@checkToken(req.token, (err, state) =>
			if err
				return cb(status: 500)
			else if state is false
				return cb(status: 403)
			else unless req.name? and req.pubkey?
				return cb(status: 400)
			user = req.name
			queue()
				.defer(@redis.zrevrange.bind(@redis), 'sortby:index', 0, 0, 'withscores', queue.D)
				.defer(@generateID.bind(@), user, queue.D)
				.await((err, data) =>
					if err
						console.err("[Add Peer]Error: ", err)
						return cb(status: 500)
					currentIndex = if data[0].length isnt 0 then parseInt(data[0][1])+1 else 0
					id = data[1]
					peerInfo =
						'user': user
						# '\n' is escaped as '*'
						'pubkey': req.pubkey.replace(/\*/g, '\n')
					queue()
						.defer(@redis.hset.bind(@redis), 'peers', id, JSON.stringify(peerInfo), queue.D)
						.defer(@redis.zadd.bind(@redis), 'sortby:index', currentIndex, id, queue.D)
						.await((err) =>
							if err
								console.err("[Redis]Error: ", err)
								cb(status: 500)
							else
								cb(status: 200)
						)
				)
		)
	removePeer: (req, cb) =>
		if typeof cb isnt 'function'
			return
		@checkToken(req.token, (err, state) =>
			if err
				return cb(status: 500)
			else if state is false
				return cb(status: 403)
			else if not req.peer?
				return cb(status: 400)
			peer = req.peer
			@generateID(peer, (err, id) =>
				if err
					return cb(status: 500)
				queue()
					.defer(@redis.hdel.bind(@redis), 'peers', id, queue.D)
					.defer(@redis.zrem.bind(@redis), 'sortby:index', id, queue.D)
					.defer(@redis.zrem.bind(@redis), 'sortby:lastping', id, queue.D)
					.await((err) =>
						if err
							console.err("[Redis]Error: ", err)
							cb(status: 500)
						else
							delete @conDB[peer] if @conDB[peer]
							delete @idDB[id] if @idDB[id]
							cb(status: 200)
					)
			)		
		)

	trackPeer: (req, cb) =>
		if typeof cb isnt 'function'
			return
		@checkToken(req.token, (err, state) =>
			if err
				return cb(status: 500)
			else if state is false
				return cb(status: 403)
			else if not req.peer?
				return cb(status: 400)
			peer = req.peer
			peerInfo = @conDB[peer]
			if peerInfo?
				peerInfo.tracking = true
			@redis.hget("peers", id, (err, data) =>
				if err
					console.error("[Redis]Error: ", err)
					cb(status: 500)
				else if data is null
					cb(status: 404)
				else
					user = JSON.parse(data)
					if not peerInfo?
						@conDB[peer] = @shallowClone(user)
						@conDB[peer].tracking = true
					)
			)

	decryptPulse: (id, ciphertext, cb) ->

		decrypt = (user) ->
			pubkey = ursa.createPublicKey(user.pubkey, 'utf8')
			message = JSON.parse pubkey.publicDecrypt(ciphertext, 'base64', 'utf8')
			if message.user isnt user.user
				cb(403)
			else
				cb(false, pubkey, message)

		if @idDB[id]
			decrypt(@idDB[id])
		else
			@redis.hget("peers", id, (err, data) =>
				if err
					console.error("[Redis]Error: ", err)
					cb(500)
				else if data is null
					cb(404)
				else
					user = JSON.parse(data)	
					@idDB[id] = user
					@conDB[user.user] = user
					decrypt(user)
			)

	generateToken: (cb) ->
		crypto.randomBytes(@config.security.tokenLength, (err, tokenBuffer) =>
			if err
				console.error("[RandomBytes]Error: ", err)
				return cb(err)
			token = @toBase64url(tokenBuffer)
			@redis.setex("token:#{token}", @config.security.tokenTTL, 1, (err) =>
				if err
					console.error("[Redis]Error: ", err)
				else
					cb(false, token)
			)
		)
	generateHash: (content, salt, cb) ->
		crypto.pbkdf2(content, salt, @config.security.hashIterations, @config.security.hashLength, (err, hash) =>
			if err
				console.error("[PBKDF2]Error: ", err)
				cb(err)
			else
				cb false, (new Buffer(hash)).toString('base64')
		)
	generateID: (user, cb) ->
		crypto.pbkdf2(user, @config.hostname, @config.security.hashIterations, @config.security.IDLength, (err, data) =>
			if err
				console.error("[PBKDF2]Error: ", err)
				cb(err)
			else
				cb(false, @toBase64url new Buffer(data))
		)
	# RFC 4648 base64url encoding
	toBase64url: (buffer) ->
		buffer.toString('base64')
			.replace(/\+/g, '-') # Convert '+' to '-'
			.replace(/\//g, '_') # Convert '/' to '_'
			.replace(/\=+$/, '') # Remove ending '='
	shallowClone: (obj) ->
		# shallowly clone a data object, disregard prototypes
		clone = {}
		clone[i] = obj[i] for own i of obj
		return clone
	checkToken: (token, cb) ->
		if not token
			cb(false, false)
		@redis.expire("token:#{token}", @config.security.tokenTTL, (err, data) =>
			if err
				console.error("[Redis]Error: ", err)
				cb(err)
			else if data is 0
				cb(false, false)
			else
				cb(false, true)
		)
	checkPassword: (password, cb) -> # cb: function(err, validity, isTemp)
		@redis.get("password", (err, data) =>
			if err
				console.error("[Redis]Error: ", err)
				cb(err)
			else if not data
				if password is @config.password
					cb(false, true, true)
				else
					cb(false, false)
			else
				try
					auth = JSON.parse(data)
					@generateHash(password, auth.salt, (err, key) =>
						console.info(auth, key)
						if err
							cb(err)
						else if key is auth.hash
							cb(false, true, false)
						else
							cb(false, false)
					)
				catch err
					console.error("[JSON]Error: ", err)
					cb(err)
		)



server = new WatchServer toml(fs.readFileSync('config.toml','utf-8'))