fs = require('fs')
https = require('https')
crypto = require('ursa')
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
			@privkey = crypto.createPrivateKey(privkey)
			@pubkey = crypto.createPublicKey(@privkey.toPublicPem())
		catch err
			log.error("[WatchServer] error reading '#{privkeyPath}': #{err}")
			return
		
		@enabled = true
	notifyTimeout: 0
	lastNotify: 0
	pulse: (externalIp) ->
		return if @notifyTimeout + @lastNotify > Date.now()
		plaintext = JSON.stringify
			'user': @user
			'ip': externalIp
			'port': @watcher.currentPort
		cipherstring = @privkey.privateEncrypt(new Buffer(plaintext), 'utf8', 'base64')
		log.debug https.request(
			'host': @server.host
			'port': @server.port or 443
			'path': "/?content="+@toBase64url(cipherstring)
			, (res) ->
				@lastNotify = Date.now()
				if(res.statusCode isnt 200) 
					log.error("[WatchServer] Unexpected pulse response")
					@notifyTimeout = 300*1000
				)
	getPeerInfo: (peer, callback) ->
		plaintext = JSON.stringify
			'user': @user
			'peer': peer
		cipherstring = @privkey.privateEncrypt(new Buffer(plaintext), 'utf8', 'base64')
		https.request(
			'host': server.host
			'port': server.port or 443
			'path': "/?content="+cipherstring.toString('base64')
			, (res) =>
				if(res.statusCode isnt 200)
					log.error("[WATCHSERVER] Unexpected response to peer request")
					callback(true)
				res.on('data', (data) ->
					peerInfo = JSON.parse @pubkey.publicDecrypt(data, 'base64', 'utf8')
					callback(false, peerInfo)
				)
			)
	toBase64url: (buffer) ->
		buffer.toString('base64')
			.replace(/\+/g, '-') # Convert '+' to '-'
			.replace(/\//g, '_') # Convert '/' to '_'
			.replace(/\=+$/, '') # Remove ending '='

exports.WatchServer = WatchServer