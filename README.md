# seald-sdk-react-native

Seald SDK for React Native integration

It is compatible with the latest versions of RN, including the Hermes engine.

## Running the demo

To run the demo, first install the dependencies:

```sh
npm install
```

Also, to run the example app, you must copy `./app/team.spec.template.ts` to `./app/team.spec.ts`, and set
the values of `apiURL`, `appId`, `JWTSharedSecretId`, `JWTSharedSecret`, `ssksURL` and `ssksBackendAppKey`.

To get these values, you must create your own Seald team on <https://www.seald.io/create-sdk>. Then, you can get the
values of `apiURL`, `appId`, `JWTSharedSecretId`, and `JWTSharedSecret`, on the `SDK` tab of the Seald dashboard
settings, and you can get `ssksURL` and `ssksBackendAppKey` on the `SSKS` tab.

Then, use the 'run' command:

```sh
npm run android
# or
npm run ios
```
