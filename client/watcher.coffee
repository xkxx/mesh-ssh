PortMap = require('./portmap').PortMap
DynDns = require('./dyndns').DynDns
WatchServer = require('./watchserver').WatchServer
IPC = require('./IPC.coffee').IPC
log = require('./log')

class Watcher
	constructor: (@options) ->
		_portMapCallback = (err, info) =>
			if err
				log.error('Port Mapping Failed'.red)
				@watchServerOnly = true
				@currentPort = null
			else
				@currentPort = info.public

			unless @watchServerOnly
				@dynDns = new DynDns(options.dyndns, info.externalIp)

			@watchServer = new WatchServer(options.watchserver, @)

		@interval = setInterval(@pulse, 30*1000)
		@internalPort = options.private
		@IPC = new IPC(@, options.socket)
		@portMap = new PortMap(options)
		if options.disable_port_maping is true
			@_portMapCallback(false, public: options.public)
		else
			@portMap.map(_portMapCallback)

	pulse: =>
		log.debug('pulse')
		[@lanIP, @gateway] = @portMap.getLanInfo()
		@watchServer.pulse() if @watchServerOnly and @watchServer.enabled
		
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