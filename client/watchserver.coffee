fs = require('fs')
https = require('https')
# https = require('http')
ursa = require('ursa')
crypto = require('crypto')
util = require('util')
log = require './log'

class WatchServer
	constructor: (options, @watcher) ->
		if not options.enabled
			log.info("[WatchServer] Service not enabled")
			return
		privkeyPath = options.privkey
		@user = options.user
		@server = options.server

		unless privkeyPath and @user and @server
			log.error("[WatchServer] Incomplete configuration")
			return

		try
			privkey = fs.readFileSync(privkeyPath)
			@privkey = ursa.createPrivateKey(privkey)
		catch err
			log.error("[WatchServer] error reading '#{privkeyPath}': #{err}")
			return

		@generateID((err) =>
			if err
				log.error('[WatchServer] error generating user ID')
			else
				@enabled = true
		)
	notifyTimeout: 0
	lastNotify: 0
	pulse: (externalIp) ->
		return if @notifyTimeout + @lastNotify > Date.now()
		@request(
			'user': @user
			'ip': externalIp
			'port': @watcher.currentPort
			, (res) =>
				return if util.isError(res)
				@lastNotify = Date.now()
				if res.statusCode isnt 200 
					log.error("[WatchServer] Unexpected pulse response, code", res.statusCode)
					@notifyTimeout = 300*1000
				)
	getPeerInfo: (peer, callback) ->
		@request(
			'user': @user
			'peer': peer
			, (res) =>
				if util.isError(res)
					return callback(res)
				if res.statusCode isnt 200
					log.error("[WatchServer] Unexpected response to peer request, code", res.statusCode)
					callback(true)
				chunks = []
				res.on('data', (chunk) =>
					chunks.push(chunk)
				)
				res.on('end', =>
					data = Buffer.concat(chunks)
					peerInfo = JSON.parse @privkey.decrypt(data).toString('utf-8')
					callback(false, peerInfo)
				)
			)
	request: (json, res_cb) ->
		cipherstring = @privkey.privateEncrypt new Buffer(JSON.stringify(json)), 'utf8'
		req = https.get(
			'host': @server.host
			'port': @server.port or 443
			'path': "/?id=#{@ID}&content=#{@toBase64url(cipherstring)}"
			, res_cb
			)
		console.info("/?id=#{@ID}&content=#{@toBase64url(cipherstring)}")
		req.on("error", (err) ->
			log.error("[WatchServer] Network error: ", err)
			res_cb(err)
			)
	generateID: (cb) ->
		crypto.pbkdf2(@user, @server.host, @server.hashIterations, @server.IDLength, (err, data) =>
			if err
				log.error("[PBKDF2]Error: ", err)
				cb(err)
			else
				@ID = @toBase64url(new Buffer(data))
				cb(false)
		)
	toBase64url: (buffer) ->
		buffer.toString('base64')
			.replace(/\+/g, '-') # Convert '+' to '-'
			.replace(/\//g, '_') # Convert '/' to '_'
			.replace(/\=+$/, '') # Remove ending '='

exports.WatchServer = WatchServer