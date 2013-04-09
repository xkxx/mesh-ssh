toml = require('tomljs')
fs = require ('fs')
Watcher = require('./watcher').Watcher

server = new Watcher toml(fs.readFileSync('config.toml','utf-8'))