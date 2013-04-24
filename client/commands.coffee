#! /usr/bin/env coffee

fs = require ('fs')
net = require('net')
path = require('path')
child_process = require('child_process')
program = require('commander')
crypto = require('ursa')
toml = require('tomljs')
prettyjson = require('prettyjson')

options = toml(fs.readFileSync('config.toml','utf-8'))

sshConnect = (user, ip, port, sshArgs) ->
	console.info("Connecting to #{user}@#{ip}:#{port} ...\n")

	sshArgs.unshift(ip, '-l', user, '-p', port)

	ssh = child_process.spawn('ssh', sshArgs, stdio: 'inherit')
	ssh.on('close', (code) ->
		console.info("\nSSH session terminated with code #{code}.")
	)

connectPeer = (dest) ->
	if not options.watchserver.enabled
		console.error("""
			WatchServer is not enabled
			Please set 'enabled = true' in section [watchserver] of config.toml
			If you wish to enable WatchServer
			""")
		return
	peer = dest.match(/^([\w-\.]+)@([\w-\.]+)$/)
	if not peer?
		if options.watchserver.aliases[dest]
			peer = options.watchserver.aliases[dest].match(/^([\w-\.]+)@([\w-\.]+)$/)
			if not peer?
				console.error("Invalid alias #{dest}")
				printConnectUsage()
				return
		else
			console.error("Invalid destination #{dest}")
			printConnectUsage()
			return

	sshArgs = if program.sshOptions then program.sshOptions.split(' ') else []
	sshArgs.unshift('-i', program.identity) if program.identity
	# to prevent ssh from complaining about IP address changes
	sshArgs.unshift('-o', "HostKeyAlias=#{peer[1]}@#{peer[2]}",
					'-o', "CheckHostIP=no"
		)

	IPCconnect(
		'type': 'connect'
		'peer': peer[2]
		, (err, info) ->
			return if err
			if info.data.lan_gateway is info.data.local_gateway
				console.info("""
					It seems that we are located in the same LAN network.
					Trying to connect with lan address ...
					""")
				sshConnect(peer[1], info.data.lan_ip, info.data.internal_port, sshArgs)
			else if info.data.port
				sshConnect(peer[1], info.data.ip, info.data.port, sshArgs)
			else
				console.error("""
						Peer did not report a public port number.
						They probably couldn't get their port forwarded by the router.
						Sorry about that.
						""")
			
	)

IPCconnect = (json, callback) ->
	cbCalled = false
	raw = ''
	connection = net.connect(
		'path': path.resolve(__dirname, options.socket)
		'allowHalfOpen': true
		)
	connection.on('connect', () ->
			connection.setNoDelay()
			connection.setEncoding('utf-8')
			connection.write JSON.stringify(json)
			connection.end()
	)
	connection.on('data', (chunk) -> raw += chunk)
	connection.on('end', =>
		try
			data = JSON.parse(raw)
		catch err
			console.error('Error connecting to backend:', err)
			cbCalled = true
			callback(err)
		if data.status isnt 'success'
			console.error('Backend Error:', data.error)
			cbCalled = true
			callback(data.error)
		else
			cbCalled = true
			callback(false, data)
	)
	connection.on('error', (err) ->
		console.error('Error connecting to backend:', err)
		cbCalled = true
		callback(err)
	)

printConnectUsage = () ->
	console.info("""
		connect usage:
			connect username@peer
			connect alias

			username, peer and alias must contain only alphanumeric characters,
			underscores '_', dashes '-' and dots '.'
			Aliases can be configured in section [watchserver.aliases] of config.toml
		""")

# Command handling

program
	.version('0.0.1')
	.option('-o, --ssh-options [options]', "other ssh options")
	.option('-i, --identity [identity_file]', "path of SSH identity file")

program.command('genkey')
	.description('generate key pair for connecting to watchserver')
	.action(->
		if fs.existsSync(options.watchserver.privkey)
			console.info("Keys already exist")
			return
		if options.watchserver.privkey
			privkeyPath = options.watchserver.privkey
		else
			console.info("'privkey' not specified in config.toml, will use default config")
			privkeyPath = "privkey.pem"
		privkey = crypto.generatePrivateKey()
		pubPem = privkey.toPublicPem()
		privPem = privkey.toPrivatePem()
		
		try
			fs.writeFileSync(privkeyPath, privPem)
		catch err
			console.error("Error writing #{privkeyPath} to disk:", err)
			return

		console.info("""
			Operation complete
			Please update your config.toml with the following:

			.  .  .

			[watchserver]

			privkey = "#{privkeyPath}"

			.  .  .

			Please add a new peer on https://YOUR_WATCHSERVER/maintainance
			with the following public key:

			#{pubPem.toString().replace(/\n/g,'*')}
			""")

	)

program.command('pubkey')
	.description('retrive public key for registration on watchserver')
	.action(->
		if options.watchserver.privkey
			privkeyPath = options.watchserver.privkey
		else
			console.info("""
				'privkey' not specified in config.toml.
				If you need to generate a new key pair, use 'genkey' command""")
			return

		try
			privkey = crypto.createPrivateKey fs.readFileSync(privkeyPath)
		catch err
			console.error("Error reading #{privkeyPath}:", err)
			return

		pubPem = privkey.toPublicPem()

		console.info("""
			Please add a new peer on https://YOUR_WATCHSERVER/maintainance
			with the following public key:

			#{pubPem.toString().replace(/\n/g,'*')}
			""")
	)

program.command('status')
	.description('show current status')
	.action(->
		IPCconnect(
			'type': "status",
			(err, info) ->
				return if err
				console.info prettyjson.render(info.data)
			)
	)

program.command('connect')
	.description('connect to peer')
	.action(connectPeer)

program.command('*')
	.description('connect to peer')
	.action(connectPeer)

program.parse(process.argv)

if program.args.length is 0
	program.help()