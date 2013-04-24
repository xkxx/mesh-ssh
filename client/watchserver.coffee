fs = require('fs')
http = require('http')
https = require('https')
ursa = require('ursa')
crypto = require('crypto')
util = require('util')
querystring = require('querystring')
wifiScanner = require('node-wifiscanner')
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
	tracking: false
	pulse: (externalIp) ->
		if @tracking is true
			# If @tracking is true, we send data every pulse regardless of whether the server is responding
			@getGeoLocation((err, geoLocation) =>
				if err
					@sendPulse(externalIp)
				else
					@sendPulse(externalIp, geoLocation)
			)
		else
			return if @notifyTimeout + @lastNotify > Date.now()
			@sendPulse(externalIp)
	sendPulse: (externalIp, geoLocation) ->
		@request(
			'user': @user
			'ip': externalIp
			'lan_ip': @watcher.lanIP
			'lan_gateway': @watcher.gateway
			'port': @watcher.currentPort,
			'internal_port': @watcher.internalPort
			'geo_location': geoLocation
			, (err, statusCode, data) =>
				@lastNotify = Date.now()
				if err or statusCode isnt 200 
					log.error("[WatchServer] Unexpected pulse response, code", statusCode)
					@notifyTimeout = 120*1000
				else
					@notifyTimeout = 0
				if data?
					@tracking = data.tracking || false
		)
	getPeerInfo: (peer, callback) ->
		@request(
			'user': @user
			'peer': peer
			, (err, statusCode, data) ->
				if err
					callback(err)
				else if statusCode isnt 200
					log.error("[WatchServer] Unexpected response to peer request, code", statusCode)
					callback(true)
				else
					callback(false, data)
			)
	request: (json, callback) ->
		cipherstring = @privkey.privateEncrypt new Buffer(JSON.stringify(json)), 'utf8'
		req = http.get(
			'host': @server.host
			'port': @server.port or 443
			'path': "/?id=#{@ID}&content=#{@toBase64url(cipherstring)}"
			, (res) ->
				chunks = []
				res.on('data', (chunk) ->
					chunks.push(chunk)
				)
				res.on('end', =>
					try 
						if chunks.length > 0
							cryptoText = Buffer.concat(chunks)
							clearText = JSON.parse @privkey.decrypt(cryptoText).toString('utf-8')
						callback(false, res.statusCode, clearText)
					catch err
						log.error("[WatchServer] Decrypt/JSON error: ", err)
						callback(err)
				)
			)
		console.info("/?id=#{@ID}&content=#{@toBase64url(cipherstring)}")
		req.on("error", (err) ->
			log.error("[WatchServer] Network error: ", err)
			callback(err)
			)
	getGeoLocation: (cb) ->
		maxCells = 10
		wifiscanner.scan((err, result) ->
			if err
				log.error("[GeoLocation] Scan Error: ", err)
				return cb(err)
			cells = ("wifi=mac:#{i.mac}|ssid:#{i.ssid}|ss:#{i.signal_level}" for i in result[0...10]).join('&')
			###
				Here we bootleg Google's browser GeoLocation API for the following reasons:
				* This tracking feature is only enabled in emergency occations.
				* Google's official API requires billing and is limited to 200 calls/day. 
				* It makes no sense signing up for billing for something that may never be used,
				and when disaster strikes 200 calls/day is simply not enough
			###
			https.get(
				'host': 'maps.googleapis.com'
				'port': 443,
				'path': "/maps/api/browserlocation/json?browser=firefox&sensor=true&" + cells
				, (res) ->
					res.setEncoding('utf-8')
					data = ''
					res.on('data', (chunk) ->
						data += chunk
					)
					res.on('end', ->
						try
							location = JSON.parse(data)
							callback(false, location)
						catch err
							log.error("[GeoLocation] JSON error: ", err)
							cb(err)
					)
			).on('error', (err) ->
				log.error("[GeoLocation] Network error: ", err)
				cb(err)
			)
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