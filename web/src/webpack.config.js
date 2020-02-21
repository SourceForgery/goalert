// Folder ops
const path = require('path')
const webpack = require('webpack')
const CopyPlugin = require('copy-webpack-plugin')

// Constants
const APP = path.join(__dirname, 'app')
const BUILD = path.join(__dirname, 'build')
const PORT = process.env.PORT || 3032

module.exports = {
  mode: 'development',
  // Paths and extensions
  entry: {
    app: APP,
  },
  output: {
    path: BUILD,
    filename: 'static/[name].js',
  },
  resolve: {
    extensions: ['.ts', '.tsx', '.js', '.jsx', '.css'],
    alias: {
      'react-dom': '@hot-loader/react-dom',
    },
  },
  // Loaders for processing different file types
  module: {
    rules: [
      {
        test: /modernizr.config.js$/,
        use: ['modernizr-loader'],
      },
      {
        test: /\.(t|j)sx?$/,
        use: [
          'react-hot-loader/webpack',
          {
            loader: 'babel-loader',
            options: {
              cacheDirectory: true,
            },
          },
          { loader: 'ifdef-loader', options: { HMR: true } },
        ],
        exclude: [/node_modules/],
        include: [APP],
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader'],
      },
      {
        test: /\.json$/,
        loader: 'json-loader',
        type: 'javascript/auto',
      },
      {
        test: /\.md$/,
        use: 'raw-loader',
      },
      {
        test: /\.(gif|png|jpe?g|svg|ico|webp)$/i,
        use: [
          {
            loader: 'file-loader',
            options: {
              name: 'static/[hash].[ext]',
            },
          },
        ],
      },
    ],
  },

  // Source maps used for debugging information
  devtool: 'inline-source-map',
  // webpack-dev-server configuration
  devServer: {
    disableHostCheck: true,
    hot: true,
    historyApiFallback: true,

    stats: 'errors-only',

    // host: HOST,
    port: PORT,

    // CopyWebpackPlugin: This is required for webpack-dev-server.
    // The path should be an absolute path to your build destination.
    // outputPath: BUILD
  },

  // Webpack plugins
  plugins: [
    new webpack.DllReferencePlugin({
      manifest: path.join(__dirname, 'build/vendorPackages.json'), // generated by webpack.dll.config.js
    }),
    new webpack.HotModuleReplacementPlugin(),
    new CopyPlugin(
      [16, 32, 64, 192].map(size => ({
        from: path.resolve(APP, `./public/favicon-${size}.png`),
        to: path.resolve(BUILD, `./static/favicon-${size}.png`),
      })),
    ),
  ],
}
