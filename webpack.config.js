const TerserPlugin = require('terser-webpack-plugin')
module.exports = {
  mode: 'production',
  entry: {
    'mcf.umd.min': {
      import: "./src/index",
      library: {
        name: "Mcf",
        type: "umd",
      },
      filename: "[name].js",
    },
  },
  output: {
    library: "Mcf",
    filename: '[name].js',
    globalObject: 'this',
  },
  module: {
    rules: [{
      test: /\.js$/,
      exclude: /(node_modules|bower_components)/,
      use: {
        loader: 'babel-loader',
        options: {
          presets: ['@babel/preset-env']
        }
      }
    }]
  },
  optimization: {
    minimize: true,
    minimizer: [new TerserPlugin({
      test: /\.js$/i,
      extractComments: false,
      terserOptions: {
        compress: {
          drop_console: false,
          drop_debugger: false,
          pure_funcs: ['console.log'],
        },
      },
    })],
  },
}