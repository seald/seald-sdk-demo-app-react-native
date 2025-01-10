# seald-sdk-react-native

Seald SDK for React Native integration

It is compatible with the latest versions of RN, including the Hermes engine.

## Install and run the demo

First, install and build all packages of the mono-repo
```sh
lerna bootstrap
lerna run pretest
```

For subsequant build, you can rebuild only the sdk-react-native package
```sh
cd packages/sdk-react-native

# Build sdk-rn
npm run build
```

Metro bundler does not accept file from a parent directory.
After every build, the new bundle files are copied into the demo app directory.

Then, install the demo dependencies:
```sh
cd example
yarn install

# On iOS, you will also need to install pod dependencies:
cd ios/
pod install # you may need to run `brew install cocoapods` first (do not install with `gem`, it is broken)
```

For android, you will need to:
- install ADB, and bind it to your PATH
- install java

For details, see : https://reactnative.dev/docs/environment-setup

Running the demo:
```sh
yarn run start # to start metro server

yarn run android # to build and install the app, it starts the metro server if not started already
# or: yarn run ios
```
