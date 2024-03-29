natpmp = require('nat-pmp')
natupnp = require('nat-upnp')
netroute = require('netroute')
os = require('os')
colors = require('colors')
log = require('./log')

class PortMap
    constructor: (@options) ->
        options.gateway ||= netroute.getGateway()
        options.private ||= 22
        options.public  ||= 8888
        options.ttl     ||= 3600

        @clients =
            pmp: natpmp.connect(options.gateway),
            upnp: natupnp.createClient()

    externalIp: (callback) ->
        @_connect((err, client, external) -> callback(err, external))

    getLanInfo: () ->
        interfaces = os.networkInterfaces()
        gateway = @getGateway()
        if gateway[0]?
            IPFamily = gateway[1]
            for addresses of interfaces
                for address in addresses
                    if address.internal is false and address.family is IPFamily
                        return [gateway[0], address.address]
                        
        return [null, null]

    # we dispatch getGateway() to include the type of address
    getGateway: (_interface) ->
        info = netroute.getInfo()
        def = info.IPv4.filter (route) ->
            return route.destination is '0.0.0.0' and (not _interface or route.interface is _interface)

        return [def[0].gateway, 'IPv4'] if def.length isnt 0

        def = info.IPv6.filter (route) ->
            return route.destination is '::0' and (not _interface or route.interface is _interface)

        return if def[0] then [def[0].gateway, 'IPv6'] else [null]

    map: (callback) ->
        options = @options
        callback = callback || ->
        onConnect = (err, client, external) ->
            if err
                return callback(err)
            portInfo =
                private: options.private,
                public: options.public,
                ttl: if client is this.clients.upnp then 0 else options.ttl

            log.info('[PortMap] Connected to WAN address: ' + external.magenta)
            log.info('[PortMap] Mapping ' + (external + ':' + options.public.toString()).magenta +
                    ' => ' + ('localhost:' + options.private.toString()).magenta)

            return client.portMapping(portInfo, (err, info) ->
                if err
                    log.error('[PortMap]', err)
                    return callback(err)

                # UPNP Returns server's response in info object
                info = options if !info.public
            )

            if Number(options.public) isnt Number(info.public)
                log.error('[PortMap]', external.magenta + ':'.magenta +
                            options.public.toString().magenta + ' unavailable'.red)
                log.warn('[PortMap] Auto-assigning public port...'.yellow)
                log.info('[PortMap] Mapped ' + (external + ':' + info.public.toString()).magenta +
                           ' => ' + ('localhost:' + options.private.toString()).magenta)
            log.info('[PortMap]', 'NAT established.'.green)
            info.externalIp = external
            callback(err, info)
        @_connect(onConnect)

    _connect: (callback) -> #callback: function(err, client, external);
        once = false
        waiting = Object.keys(@clients).length

        Object.keys(@clients).forEach((key) =>
            client = @clients[key];

            client.externalIp (err, external) -> 
                waiting--
                return if once

                # Ignore errors if we have reserve choices
                return if err && waiting > 0

                log.debug(err, external)

                # Invoke callback only once
                once = true

                if err
                    log.error('[PortMap]', err)
                    return callback(err)

                if typeof external is 'string'
                    callback(null, client, external)
                else 
                    callback(null, client, external.ip.join('.'))
        )

exports.PortMap = PortMap