net = require('net')
path = require('path')
log = require('./log')

class IPC
	constructor: (@watcher, sockPath) ->
		if not sockPath
			log.error("[IPC] 'socket' not specified. IPC cannot continue")
			return
		@server = net.createServer(allowHalfOpen: true, @listener.bind(@))
		@server.listen path.resolve(__dirname, sockPath)
		@server.on('error', (err) ->
			if err.code is 'EADDRINUSE'
				log.error("[IPC] Socket is in use. Please make sure you are not running multiple instances, 
and then delete #{path.resolve(__dirname, sockPath)}".red)
				process.exit(1)
		)
		process.on('exit', ->
			try @server.close()
			)
	listener: (connection) ->
		connection.setNoDelay()
		connection.setEncoding('utf-8')
		raw = ''
		connection.on('data', (chunk) -> raw += chunk)
		connection.on('end', =>
			try
				data = JSON.parse(raw)
			catch err
				log.error('[IPC] error parsing json:', err)
				connection.end(JSON.stringify(
					"status": "error"
					"error": err 
					))
				return
			switch data.type
				when 'connect'
					if not @watcher.watchServer.enabled
						connection.end(JSON.stringify(
									"status": "error"
									"error": "watchserver not available" 
								))
						return
					@watcher.watchServer.getPeerInfo(data.peer, (err, info) =>
							if err
								log.error("[IPC] error getting info about peer #{data.peer}:", err)
								connection.end(JSON.stringify(
									"status": "error"
									"error": err 
								))
							else
								log.info("[IPC] CLI requested info about peer #{data.peer}")
								connection.end(JSON.stringify(
									"status": "success"
									"data": info 
								))
						)
				when 'status'
					connection.end(JSON.stringify(
									"status": "success"
									"data":
										"port-map": if @watcher.currentPort then true else false
										"current-port": @watcher.currentPort
										"exteral-ip": @watcher.exteralIp
								))
				else
					log.error("[IPC] recognized request:", data.type)
					connection.end(JSON.stringify(
									"status": "error"
									"error": "recognized request" 
								))

			)
		connection.on('error', (err) -> log.error('[IPC] socket error', err))

exports.IPC = IPC