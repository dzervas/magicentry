// webpack.config.js
const path = require('path');

module.exports = [
	{
		entry: './static/webauthn.js', // Your entry point file
		output: {
			filename: 'webauthn.build.js',
			path: path.resolve(__dirname, 'static'),
		}
	}
];
