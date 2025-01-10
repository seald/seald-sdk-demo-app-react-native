module.exports = function (api) {
  api.cache(false)
  return {
    presets: ['module:@react-native/babel-preset'],
    plugins: [
      ['@babel/plugin-transform-private-methods', { loose: true }],
      [
        'module-resolver',
        {
          alias: {
            crypto: 'react-native-quick-crypto',
            stream: 'readable-stream',
            buffer: '@craftzdog/react-native-buffer'
          }
        }
      ]
    ]
  }
}
