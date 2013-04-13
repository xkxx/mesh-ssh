PortMap = require('./portmap').PortMap
DynDns = require('./dyndns').DynDns
WatchServer = require('./watchserver').WatchServer
IPC = require('./IPC.coffee').IPC
log = require('./log')

class Watcher
	constructor: (@options) ->
		@IPC = new IPC(@, options.socket)
		@portMap = new PortMap(options)
		@portMap.map((err, info) =>
			if err
				log.error('Port Mapping Failed'.red)
				@watchServerOnly = true
				@currentPort = null
			else
				@currentPort = info.public

			unless @watchServerOnly
				@dynDns = new DynDns(options.dyndns, info.externalIp)

			@watchServer = new WatchServer(options.watchserver, @)

			@interval = setInterval(@pulse.bind(@), 30*1000)
		)

	pulse: ->
		@watchServer.pulse() if @watchServerOnly and @watchServer.enabled
		log.debug('pulse')
		@portMap.externalIp((err, external) =>
			@externalIp = external
			if err
				log.error('Error getting external IP'.red)
			if @dynDns.enabled
				@dynDns.pulse(external)
			if @watchServer.enabled
				@watchServer.pulse(external)
		)
	# data properties
	currentPort: null
	externalIp: null

exports.Watcher = Watcher