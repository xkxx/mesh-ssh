https = require('https')
log = require('./log')

servers = 
	'noip':
		'host': "dynupdate.no-ip.com"
		'path': "/nic/update"
	'dnsdyn':
		'host': "www.dnsdynamic.org"
		'path': "/api/"
userAgent = "Free SSH/0.1 xkxiang@gmail.com"

class DynDns
	constructor: (options, @external) ->
		if not options.enabled
			log.info("[DynDNS] Service not enabled")
			return

		@service = options.service
		@user = options.user
		@password = options.password
		@hostname = options.hostname
		unless @service and @user and @password and @hostname
			log.info("[DynDNS] Incomplete configuration")
			return
		notify(external)
		@enabled = true

	notifyTimeout: 0
	lastNotify: 0
	pulse: (external) ->
		if external isnt @external
			notify(external)
	notify: (external) ->
		return if notifyTimeout + lastNotify > Date.now()
		https.request(
			'host': servers[@service].host
			'path': servers[@service].path + "?hostname=#{@hostname}&myip=#{external}"
			'port': 443
			'auth': "#{user}:#{password}"
			'headers':
				'user-agent': userAgent
			, (res) =>
				lastNotify = Date.now()
				log.debug('[DynDNS] STATUS: ' + res.statusCode)
				res.setEncoding('utf8')
				res.on('data', (data) ->
    				return if data[0..3] is "good"
    				return if data[0..4] is "nochg"
    				switch data
    					when "nohost"
    						log.error("[DynDNS] Hostname does not exist")
    						stopInterval(@interval)
    					when "badauth"
    						log.error("[DynDNS] Authentication failed")
    						stopInterval(@interval)
    					when "badagent"
    						log.error("[DynDNS] Client is not allowed")
    						stopInterval(@interval)
    					when "abuse"
    						log.error("[DynDNS] User is banned due to abuse")
    						stopInterval(@interval)
    					when "dnserr"
    						log.error("[DynDNS] Remote DNS server failure")
    						notifyTimeout = 1800*1000
    					when "911"
    						log.error("[DynDNS] Remote server failure")
    						notifyTimeout = 1800*1000
    			)
			)

exports.DynDns = DynDns