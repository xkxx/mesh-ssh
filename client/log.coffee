colors = require('colors')

logger = exports;

logger.debugLevel |= 0;
logger.levels = [
	['debug', 'grey']
	['info', 'white']
	['warn', 'yellow']
	['error', 'red']
]

logger.levels.forEach((level, index) ->
	logger[level[0]] = (message...) ->
		if index >= logger.debugLevel
			console.log ('['+level[0].toUpperCase() + ']')[level[1]], message...
)