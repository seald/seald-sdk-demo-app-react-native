import { Buffer } from '@craftzdog/react-native-buffer'

global.Buffer = Buffer

import { Text, View } from 'react-native'
import { useEffect, useState } from 'react'

import SealdSDK from '@seald-io/sdk/react-native/seald-sdk-react-native.bundle'
import SealdSsksTMRPlugin from '@seald-io/sdk-plugin-ssks-2mr/react-native/seald-sdk-plugin-ssks-2mr.bundle.js'
import SealdSsksPasswordPlugin from '@seald-io/sdk-plugin-ssks-password/react-native/seald-sdk-plugin-ssks-password.bundle.js'
import testCredentials from './team.spec'
import {
  JWTBuilder,
  JwtBuilder
} from './jwtBuilder'
import SSKSBackend from './ssks-backend'
import AsyncStorage from '@react-native-async-storage/async-storage'
import * as crypto from 'crypto'
import assert from 'assert'

import { readFileStream, writeFileStream } from './streams'
import RNFS from 'react-native-fs'
import { promises as streamPromise } from 'stream'

export const randomString = (length = 10) => {
  return crypto.randomBytes(length)
    .toString('base64')
    .replace(/[^a-z0-9]/gi, '')
    .slice(0, length)
    .toLowerCase()
}

const UUIDRegexp = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const isUUID = (str: string): boolean => UUIDRegexp.test(str)

export default function Index () {
  const testSealdSsksPassword = async (jwtBuilder: JWTBuilder) => {
    setHasStartedSSKSPassword(true)
    try {
      // This SDK instance will be in memory only. No persistent database will be created (See `databasePath` and `databaseKey` arguments to do so)
      const sdkSSKS = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, plugins: [SealdSsksPasswordPlugin(testCredentials.ssksURL)] })
      const userSSKSAccountInfo = await sdkSSKS.initiateIdentity({ signupJWT: await jwtBuilder.signupJWT(), displayName: 'rn-demo-user-pass', deviceName: 'rn-demo-device-pass' })
      sdkSSKS.setLogLevel('silly')

      const userIdentity = await sdkSSKS.exportIdentity()

      // Test with password
      const userIdPassword = `user-${randomString(10)}`
      const userPassword = randomString(10)

      // Saving the identity with a password
      const ssksId1 = await sdkSSKS.ssksPassword.saveIdentity({ userId: userIdPassword, password: userPassword })
      assert(ssksId1 !== '')

      // Retrieving the identity with the password
      const sdkSSKSInst2 = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, plugins: [SealdSsksPasswordPlugin(testCredentials.ssksURL)] })
      sdkSSKSInst2.setLogLevel('silly')

      const retrievedIdentity = await sdkSSKSInst2.ssksPassword.retrieveIdentity({ userId: userIdPassword, password: userPassword })
      const inst2Identity = await sdkSSKSInst2.exportIdentity()
      assert(retrievedIdentity.sealdId === userSSKSAccountInfo.sealdId)
      assert(inst2Identity.equals(userIdentity))

      // Changing the password
      const newPassword = 'newPassword'
      const ssksId1b = await sdkSSKSInst2.ssksPassword.changeIdentityPassword({ userId: userIdPassword, currentPassword: userPassword, newPassword })
      assert(ssksId1b !== ssksId1)

      // The previous password does not work anymore
      const sdkSSKSInst3 = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, plugins: [SealdSsksPasswordPlugin(testCredentials.ssksURL)] })
      sdkSSKSInst3.setLogLevel('silly')

      await assert.rejects(sdkSSKSInst3.ssksPassword.retrieveIdentity({ userId: userIdPassword, password: userPassword }), /Unable to load identity. Have you changed your password\?/)

      // Retrieving with the new password works
      const retrieveNewPassword = await sdkSSKSInst3.ssksPassword.retrieveIdentity({ userId: userIdPassword, password: newPassword })
      assert(retrieveNewPassword.sealdId === userSSKSAccountInfo.sealdId)
      const inst3Identity = await sdkSSKSInst3.exportIdentity()
      assert(inst3Identity.equals(userIdentity))

      // Test with raw keys
      const userIdRawKeys = `user-${randomString(10)}`
      const rawEncryptionKey = await sdkSSKS.utils.generateB64EncodedSymKey()
      const rawStorageKey = randomString(32)

      // Saving identity with raw keys
      const ssksId2 =
        await sdkSSKS.ssksPassword.saveIdentity({
          userId: userIdRawKeys,
          rawStorageKey,
          rawEncryptionKey
        })
      assert(ssksId2 !== '')

      // Retrieving the identity with raw keys
      const sdkSSKSInst4 = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, plugins: [SealdSsksPasswordPlugin(testCredentials.ssksURL)] })
      sdkSSKSInst4.setLogLevel('silly')
      const retrievedFromRawKeys =
        await sdkSSKSInst4.ssksPassword.retrieveIdentity({
          userId: userIdRawKeys,
          rawStorageKey,
          rawEncryptionKey
        })
      assert(retrievedFromRawKeys.sealdId === userSSKSAccountInfo.sealdId)
      const inst4Identity = await sdkSSKSInst4.exportIdentity()
      assert(inst4Identity.equals(userIdentity))

      // Deleting the identity by saving an empty `Data`
      const ssksId2b =
        await sdkSSKSInst4.ssksPassword.saveIdentity({
          userId: userIdRawKeys,
          rawStorageKey,
          rawEncryptionKey,
          identity: Buffer.alloc(0)
        })
      assert(ssksId2b === ssksId2)

      const sdkSSKSInst5 = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, plugins: [SealdSsksPasswordPlugin(testCredentials.ssksURL)] })
      sdkSSKSInst5.setLogLevel('silly')
      // After deleting the identity, cannot retrieve anymore
      await assert.rejects(sdkSSKSInst5.ssksPassword.retrieveIdentity({
        userId: userIdRawKeys,
        rawStorageKey,
        rawEncryptionKey
      }), /Unable to load identity. Have you changed your password\?/)

      await sdkSSKS.close()
      await sdkSSKSInst2.close()
      await sdkSSKSInst3.close()
      await sdkSSKSInst4.close()
      await sdkSSKSInst5.close()

      console.log('SSKS Password tests success!')
      setHasFinishedSSKSPassword(true)
    } catch (error) {
      console.error('SSKS Password tests FAILED')
      console.error(error)
      console.error(error.stack)
      setHasErrorSSKSPassword(error.toString())
      setHasFinishedSSKSPassword(true)
    }
  }

  const testSealdSsksTMR = async (jwtBuilder: JWTBuilder) => {
    setHasStartedSSKSTMR(true)
    try {
      // This SDK instance will be in memory only. No persistent database will be created (See `databasePath` and `databaseKey` arguments to do so)
      const sdkTMR = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, plugins: [SealdSsksTMRPlugin(testCredentials.ssksURL)] })
      const userTMRAccountInfo = await sdkTMR.initiateIdentity({ signupJWT: await jwtBuilder.signupJWT(), displayName: 'rn-demo-user-tmr', deviceName: 'rn-demo-device-tmr' })
      sdkTMR.setLogLevel('silly')

      const initialString = 'a message that needs to be encrypted!'
      const encryptedMessage = await sdkTMR.encryptMessage(initialString, { sealdIds: [userTMRAccountInfo.sealdId] })

      // rawTMRSymKey is a secret, generated and stored by your _backend_, unique for the user.
      // It can be retrieved by client-side when authenticated (usually as part of signup/sign-in call response).
      // This *MUST* be a cryptographically random string of 64 bytes.
      const rawTMRSymKey = await sdkTMR.utils.generateB64EncodedSymKey()

      // This DummyBackend represent your backend. It will be used to simulate what your backend should do at signup/sign-in
      const yourCompanyDummyBackend = SSKSBackend(testCredentials.ssksURL, fetch, testCredentials.appId, testCredentials.ssksBackendAppKey)

      // userId is the ID of the user in your app.
      const userId = `rn-tmr-user-${randomString(10)}`
      // userIdentity is the user's exported identity that you want to store on SSKS
      const userIdentity = await sdkTMR.exportIdentity()

      // Define an AuthFactor: the user's email address.
      // AuthFactor can be an email `AuthFactorType.EM` or a phone number `AuthFactorType.SMS`
      const userEM = `email-${randomString(15)}@test.com`
      const authFactor = {
        type: 'EM',
        value: userEM
      }

      // The app backend creates an SSKS authentication session to save the identity.
      // This is the first time that this email is storing an identity, so the returned `must_authenticate` is false.

      const authSessionSave = await yourCompanyDummyBackend.challengeSend(
        userId,
        authFactor,
        {
          createUser: true,
          forceAuth: false,
          // `fakeOtp` is only on the staging server, to force the challenge to be 'aaaaaaaa'.
          // In production, you cannot use this.
          fakeOtp: true
        }
      )
      assert(!authSessionSave.mustAuthenticate)
      // The response to the signup call should include `authSessionSave.sessionId` and `rawTMRSymKey`

      // The app can then save its Seald identity:
      // No challenge necessary because `must_authenticate` is false.
      const saveIdentityRes1 = await sdkTMR.ssks2MR.saveIdentity({ userId, sessionId: authSessionSave.sessionId, authFactor, twoManRuleKey: rawTMRSymKey })
      assert(isUUID(saveIdentityRes1.id))
      assert(isUUID(saveIdentityRes1.authenticatedSessionId))

      // At first sign-in, your backend creates another SSKS session to retrieve the identity.
      // The identity is already saved, so `must_authenticate` is true.
      const authSessionRetrieve = await yourCompanyDummyBackend
        .challengeSend(
          userId,
          authFactor,
          {
            createUser: true,
            forceAuth: false,
            // `fakeOtp` is only on the staging server, to force the challenge to be 'aaaaaaaa'.
            // In production, you cannot use this.
            fakeOtp: true
          }
        )
      assert(authSessionRetrieve.mustAuthenticate)

      // The app can then retrieving identity. Challenge is necessary for this.
      const sdkTMRInst2 = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, plugins: [SealdSsksTMRPlugin(testCredentials.ssksURL)] })
      sdkTMRInst2.setLogLevel('silly')
      const retrievedNotAuth = await sdkTMRInst2.ssks2MR.retrieveIdentity({ userId, sessionId: authSessionRetrieve.sessionId, authFactor, challenge: testCredentials.ssksTMRChallenge, twoManRuleKey: rawTMRSymKey })
      assert(retrievedNotAuth.accountInfo.sealdId === userTMRAccountInfo.sealdId)
      assert(isUUID(retrievedNotAuth.authenticatedSessionId))

      const decryptedMessage2 = await sdkTMRInst2.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessage2)

      // If initial key has been saved without being fully authenticated, the SDK renew the key and automatically save the new one.

      // The identity has changed due to the key renewal
      const identitySecondKey = await sdkTMRInst2.exportIdentity()
      assert(!identitySecondKey.equals(userIdentity))

      // To save the newly renewed identity on the server, you can use the `authenticatedSessionId` from the response to `retrieveIdentity`, with no challenge
      const saveIdentityRes2 = await sdkTMRInst2.ssks2MR.saveIdentity({ userId, sessionId: retrievedNotAuth.authenticatedSessionId, authFactor, twoManRuleKey: rawTMRSymKey })
      assert(saveIdentityRes2.id === saveIdentityRes1.id)
      assert(isUUID(saveIdentityRes2.authenticatedSessionId))

      // For later sign-in, this new saved identity can be retrieve in the same way:
      // Once the user is authed against your backend, your backend send the challenge
      const authSessionRetrieve2 = await yourCompanyDummyBackend
        .challengeSend(
          userId,
          authFactor,
          {
            createUser: false,
            forceAuth: false,
            // `fakeOtp` is only on the staging server, to force the challenge to be 'aaaaaaaa'.
            // In production, you cannot use this.
            fakeOtp: true
          }
        )
      assert(authSessionRetrieve2.mustAuthenticate)
      const sdkTMRInst3 = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, plugins: [SealdSsksTMRPlugin(testCredentials.ssksURL)] })
      sdkTMRInst3.setLogLevel('silly')

      const retrievedSecondKey = await sdkTMRInst3.ssks2MR.retrieveIdentity({ userId, sessionId: authSessionRetrieve2.sessionId, authFactor, challenge: testCredentials.ssksTMRChallenge, twoManRuleKey: rawTMRSymKey })
      assert(retrievedSecondKey.accountInfo.sealdId === userTMRAccountInfo.sealdId)
      assert(isUUID(retrievedSecondKey.authenticatedSessionId))
      // The identity has been stored while authenticated by sdkTMRInst2. The key is therefore not renewed during this retrieval.
      const sdkTMRInst3Identity = await sdkTMRInst3.exportIdentity()
      assert(identitySecondKey.equals(sdkTMRInst3Identity))

      const decryptedMessage3 = await sdkTMRInst3.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessage3)

      // Try retrieving with another SealdSsksTMRPlugin instance
      const sdkTMRInst4 = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, plugins: [SealdSsksTMRPlugin(testCredentials.ssksURL)] })
      sdkTMRInst4.setLogLevel('silly')

      const authSessionRetrieve3 = await yourCompanyDummyBackend
        .challengeSend(
          userId,
          authFactor,
          {
            createUser: false,
            forceAuth: false,
            // `fakeOtp` is only on the staging server, to force the challenge to be 'aaaaaaaa'.
            // In production, you cannot use this.
            fakeOtp: true
          }
        )
      assert(authSessionRetrieve3.mustAuthenticate)
      const inst4Retrieve = await sdkTMRInst4.ssks2MR.retrieveIdentity({ userId, sessionId: authSessionRetrieve3.sessionId, authFactor, challenge: testCredentials.ssksTMRChallenge, twoManRuleKey: rawTMRSymKey })
      assert(inst4Retrieve.accountInfo.sealdId === userTMRAccountInfo.sealdId)
      assert(isUUID(inst4Retrieve.authenticatedSessionId))

      const decryptedMessage4 = await sdkTMRInst4.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessage4)

      await sdkTMR.close()
      await sdkTMRInst2.close()
      await sdkTMRInst3.close()
      await sdkTMRInst4.close()

      console.log('SSKS TMR tests success!')
      setHasFinishedSSKSTMR(true)
    } catch (error) {
      console.error('SSKS TMR tests FAILED')
      console.error(error)
      console.error(error.stack)
      setHasErrorSSKSTMR(error.toString())
      setHasFinishedSSKSTMR(true)
    }
  }

  const testSealdSDK = async (jwtBuilder: JWTBuilder) => {
    setHasStartedSDK(true)
    try {
      // The Seald SDK uses a local database that will persist on disk.
      // When instantiating a SealdSDK, it is highly recommended to set a symmetric key to encrypt this database.
      // In an actual app, it should be generated at signup,
      // either on the server and retrieved from your backend at login,
      // or on the client-side directly and stored in the system's keychain.
      // WARNING: This should be a cryptographically random buffer of 64 bytes.
      const databaseKey = crypto.randomBytes(64).toString('base64')

      // let's instantiate 3 SealdSDK. They will correspond to 3 users that will exchange messages.
      const sdk1 = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, databasePath: 'sdk1', databaseKey })
      sdk1.setLogLevel('silly')
      const sdk2 = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, databasePath: 'sdk2', databaseKey, plugins: [SealdSsksTMRPlugin(testCredentials.ssksURL)] })
      sdk2.setLogLevel('silly')
      const sdk3 = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, databasePath: 'sdk3', databaseKey })
      sdk3.setLogLevel('silly')

      // retrieve info about current user before creating a user should throw an error
      await assert.rejects(sdk1.getCurrentAccountInfo, /Error: This SDK instance is not initialized./)

      // Create the 3 accounts. Again, the signupJWT should be generated by your backend
      const user1AccountInfo = await sdk1.initiateIdentity({ signupJWT: await jwtBuilder.signupJWT(), displayName: 'rn-demo-user-1', deviceName: 'rn-demo-device-1' })
      const user2AccountInfo = await sdk2.initiateIdentity({ signupJWT: await jwtBuilder.signupJWT(), displayName: 'rn-demo-user-2', deviceName: 'rn-demo-device-2' })
      const user3AccountInfo = await sdk3.initiateIdentity({ signupJWT: await jwtBuilder.signupJWT(), displayName: 'rn-demo-user-3', deviceName: 'rn-demo-device-3' })

      // retrieve info about current user after creating a user should return account info:
      const retrieveAccountInfo = await sdk1.getCurrentAccountInfo()
      assert.ok(retrieveAccountInfo !== null)
      assert.ok(retrieveAccountInfo.sealdId === user1AccountInfo.sealdId)
      assert.ok(retrieveAccountInfo.deviceId === user1AccountInfo.deviceId)

      // Create group: https://docs.seald.io/sdk/guides/5-groups.html
      const groupName = 'group-1'
      const groupMembers = [user1AccountInfo.sealdId]
      const groupAdmins = [user1AccountInfo.sealdId]
      const { id: groupId } = await sdk1.createGroup({ groupName, members: { sealdIds: groupMembers }, admins: { sealdIds: groupAdmins } })

      // Manage group members and admins
      // user1 add user2 as group member
      await sdk1.addGroupMembers(groupId, { sealdIds: [user2AccountInfo.sealdId] })
      // user1 adds user3 as group member and group admin
      await sdk1.addGroupMembers(groupId, { sealdIds: [user3AccountInfo.sealdId] }, { sealdIds: [user3AccountInfo.sealdId] })
      // user3 can remove user2
      await sdk3.removeGroupMembers(groupId, { sealdIds: [user2AccountInfo.sealdId] })
      // user3 can remove user1 from admins
      await sdk3.setGroupAdmins(groupId, {
        addToAdmins: {},
        removeFromAdmins: { sealdIds: [user1AccountInfo.sealdId] }
      })

      // Create encryption session: https://docs.seald.io/sdk/guides/6-encryption-sessions.html
      // user1, user2, and group as recipients
      // Default rights for the session creator (if included as recipients without RecipientRights):
      // read = true, forward = true, revoke = true
      // Default rights for any other recipient:  read = true, forward = true, revoke = false
      const es1SDK1 = await sdk1.createEncryptionSession({ sealdIds: [user1AccountInfo.sealdId, user2AccountInfo.sealdId, groupId] }, { useCache: false })

      // The SealdEncryptionSession object can encrypt and decrypt for user1
      const initialString = 'a message that needs to be encrypted!'
      const encryptedMessage = await es1SDK1.encryptMessage(initialString)
      const decryptedMessage = await es1SDK1.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessage)

      // Using two-man-rule accesses

      // Add TMR accesses to the session, then, retrieve the session using it.
      // Create TMR a recipient
      const rand = randomString(5)
      const userEM = `tmr-em-swift-${rand}@test.com`
      const tmrAuthFactor = { value: userEM, type: 'EM' }

      // WARNING: This should be a cryptographically random buffer of 64 bytes.
      const rawOverEncryptionKey = await sdk1.utils.generateB64EncodedSymKey()

      const tmrRecipient = {
        authFactor: tmrAuthFactor,
        rawOverEncryptionKey
      }

      // Add the TMR access
      const addedTMRId = await es1SDK1.addTmrAccess(tmrRecipient)
      assert(isUUID(addedTMRId))

      // Retrieve the TMR JWT
      const ssksBackend = SSKSBackend(testCredentials.ssksURL, fetch, testCredentials.appId, testCredentials.ssksBackendAppKey)

      // The app backend creates an SSKS authentication session.
      // This is the first time that this email is authenticating onto SSKS, so `mustAuthenticate` would be false,
      // but we force auth because we want to convert TMR accesses.
      const tmrSession = await ssksBackend.challengeSend(
        user2AccountInfo.sealdId,
        tmrAuthFactor,
        {
          createUser: true,
          forceAuth: true,
          // `fakeOtp` is only on the staging server, to force the challenge to be 'aaaaaaaa'.
          // In production, you cannot use this.
          fakeOtp: true
        }
      )
      assert(tmrSession.mustAuthenticate)

      // Retrieve a JWT associated with the authentication factor from SSKS
      const tmrJWT = await sdk2.ssks2MR.getFactorToken({
        sessionId: tmrSession.sessionId,
        authFactor: tmrAuthFactor,
        challenge: testCredentials.ssksTMRChallenge
      })

      // Retrieve the encryption session using the JWT
      const tmrES = await sdk2.retrieveEncryptionSessionByTmr(es1SDK1.sessionId, tmrJWT.token, rawOverEncryptionKey, { useCache: false, tryIfMultiple: true })
      const decryptedMessageTmrES = await tmrES.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessageTmrES)

      // Convert the TMR accesses
      await sdk2.convertTmrAccesses(tmrJWT.token, rawOverEncryptionKey, { deleteOnConvert: true })

      // After conversion, sdk2 can retrieve the encryption session directly.
      const classicES = await sdk2.retrieveEncryptionSession({
        sessionId: es1SDK1.sessionId,
        useCache: false,
        lookupProxyKey: false,
        lookupGroupKey: false
      })
      const decryptedMessageClassicES = await classicES.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessageClassicES)

      // Using proxy sessions: https://docs.seald.io/sdk/guides/proxy-sessions.html

      // Create proxy sessions:
      // user1 needs to be a recipient of this session in order to be able to add it as a proxy session
      const proxySession1 = await sdk1.createEncryptionSession({ sealdIds: [user1AccountInfo.sealdId, user3AccountInfo.sealdId] }, { useCache: false })
      await es1SDK1.addRecipients({ proxySessions: [proxySession1.sessionId] })

      // user1 needs to be a recipient of this session in order to be able to add it as a proxy session
      const proxySession2 = await sdk1.createEncryptionSession({ sealdIds: [user1AccountInfo.sealdId, user2AccountInfo.sealdId] }, { useCache: false })
      await es1SDK1.addRecipients({ proxySessions: [proxySession2.sessionId] })

      // user1 can parse/retrieve the EncryptionSession from the encrypted message
      const es1SDK1FromMessId = await sdk1.utils.retrieveEncryptionSessionId({ encryptedMessage })
      assert(es1SDK1FromMessId === es1SDK1.sessionId)
      const es1SDK1RetrieveFromMess = await sdk1.retrieveEncryptionSession({
        encryptedMessage,
        useCache: false,
        lookupProxyKey: false,
        lookupGroupKey: false
      })
      assert(es1SDK1RetrieveFromMess.sessionId === es1SDK1.sessionId)
      const decryptedMessageFromMess = await es1SDK1RetrieveFromMess.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessageFromMess)

      // Create a test file on disk that we will encrypt/decrypt using stream
      // To do so, we will use react-native-fs, and the helpers `streams.js`

      // We start by defining files paths
      const clearFilepath = RNFS.DocumentDirectoryPath + '/test.txt'
      const encryptedFilePath = RNFS.DocumentDirectoryPath + '/test_enc.txt'
      const decryptedFilePath = RNFS.DocumentDirectoryPath + '/test_dec.txt'
      // This demo expect a clean directory, so we make sure that it is:
      await RNFS.unlink(clearFilepath).catch(err => console.log('clearFilepath', err))
      await RNFS.unlink(encryptedFilePath).catch(err => console.log('encryptedFilePath', err))
      await RNFS.unlink(decryptedFilePath).catch(err => console.log('decryptedFilePath', err))

      // We create a file of 10Mb
      const randBuff = crypto.randomBytes(10 * 1024 * 1024)
      await RNFS.writeFile(clearFilepath, randBuff.toString('base64'), 'base64')

      // Create a stream that will read the file: `clearFileStream`.
      const clearFileStream = readFileStream(clearFilepath)
      // Pipe it to a stream that will encrypt the file: `encryptStream`. (The sdk.encryptFile do the piping)
      const encryptStream = await es1SDK1.encryptFile(clearFileStream, { filename: 'test.txt', progressCallback: console.log, fileSize: randBuff.length })
      // Pipe `encryptStream` to a stream that write the encrypted file on disk.
      // Then we await the end of stream.
      await streamPromise.pipeline(encryptStream, writeFileStream(encryptedFilePath))

      // Read the encrypted file as stream
      const encFileStream = readFileStream(encryptedFilePath)
      // Create a decrypt stream. It returns an object with the stream (key `data`), and some other infos: the original filename, file size, sessionId, file type.
      const decryptInfo = await es1SDK1.decryptFile(encFileStream)

      // Pipe decrypt stream to a stream that write the encrypted file on disk.
      // Then we await the end of stream.
      await streamPromise.pipeline(decryptInfo.data, writeFileStream(decryptedFilePath))

      // Check that the decrypted file is the same as the encrypted:
      const decryptedBuff = await RNFS.readFile(decryptedFilePath, 'base64')
      assert(randBuff.equals(Buffer.from(decryptedBuff, 'base64')))
      assert(decryptInfo.sessionId === es1SDK1.sessionId)

      // user2 can retrieve the encryptionSession from the session ID.
      const es1SDK2 = await sdk2.retrieveEncryptionSession({
        sessionId: es1SDK1.sessionId,
        useCache: false,
        lookupProxyKey: false,
        lookupGroupKey: false
      })
      const decryptedMessageSDK2 = await es1SDK2.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessageSDK2)

      // user3 cannot retrieve the SealdEncryptionSession with lookupGroupKey set to false.
      await assert.rejects(
        sdk3.retrieveEncryptionSession({
          encryptedMessage,
          useCache: false,
          lookupProxyKey: false,
          lookupGroupKey: false
        }),
        /GO_NO_TOKEN_FOR_YOU_API — NO_TOKEN_FOR_YOU — Can't decipher this message — undefined on undefined/
      )

      // user3 can retrieve the encryptionSession from the encrypted message through the group.
      const es1SDK3FromGroup = await sdk3.retrieveEncryptionSession({
        encryptedMessage,
        useCache: false,
        lookupProxyKey: false,
        lookupGroupKey: true
      })
      assert(es1SDK3FromGroup.retrievalDetails.groupId === groupId)
      const decryptedMessageSDK3 = await es1SDK3FromGroup.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessageSDK3)

      // user3 removes all members of "group-1". A group without member is deleted.
      await sdk3.removeGroupMembers(groupId, { sealdIds: [user1AccountInfo.sealdId, user3AccountInfo.sealdId] })

      // user3 could retrieve the previous encryption session only because "group-1" was set as recipient.
      // As the group was deleted, it can no longer access it.
      // user3 still has the encryption session in its cache, but we can disable it.
      await assert.rejects(
        sdk3.retrieveEncryptionSession({
          encryptedMessage,
          useCache: false,
          lookupProxyKey: false,
          lookupGroupKey: true
        }),
        /GO_NO_TOKEN_FOR_YOU_API — NO_TOKEN_FOR_YOU — Can't decipher this message — undefined on undefined/
      )

      // user3 can still retrieve the session via proxy.
      const es1SDK3FromProxy = await sdk3.retrieveEncryptionSession({
        encryptedMessage,
        useCache: false,
        lookupProxyKey: true,
        lookupGroupKey: false
      })
      assert(es1SDK3FromProxy.retrievalDetails.proxySessionId === proxySession1.sessionId)
      const decryptedMessageFromProxy = await es1SDK3FromProxy.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessageFromProxy)

      // user2 adds user3 as recipient of the encryption session.
      const respAdd = await es1SDK2.addRecipients({ sealdIds: [user3AccountInfo.sealdId] })
      assert(Object.keys(respAdd.addedRecipients).length === 1)
      assert(respAdd.addedRecipients[user3AccountInfo.deviceId].status === 200)

      // user3 can now retrieve it without group or proxy.
      const es1SDK3 = await sdk3.retrieveEncryptionSession({
        sessionId: es1SDK1.sessionId,
        useCache: false,
        lookupProxyKey: false,
        lookupGroupKey: false
      })
      const decryptedMessageAfterAdd = await es1SDK3.decryptMessage(encryptedMessage)
      assert(initialString === decryptedMessageAfterAdd)

      // user1 revokes user3 and proxy1 from the encryption session.
      const respRevoke = await es1SDK1.revokeRecipients({
        sealdIds: [user3AccountInfo.sealdId],
        proxySessions: [proxySession1.sessionId]
      })
      assert(Object.keys(respRevoke.sealdIds).length === 1)
      assert(respRevoke.sealdIds[user3AccountInfo.sealdId] === 'ok')
      assert(Object.keys(respRevoke.proxySessions).length === 1)
      assert(respRevoke.proxySessions[proxySession1.sessionId] === 'ok')

      // user3 cannot retrieve the session anymore, even with proxy or group
      await assert.rejects(
        sdk3.retrieveEncryptionSession({
          encryptedMessage,
          useCache: false,
          lookupProxyKey: true,
          lookupGroupKey: true
        }),
        /GO_NO_TOKEN_FOR_YOU_API — NO_TOKEN_FOR_YOU — Can't decipher this message — undefined on undefined/
      )

      // user1 revokes all other recipients from the session
      const respRevokeOther = await es1SDK1.revokeRecipients({ sealdIds: [user2AccountInfo.sealdId, groupId], proxySessions: [proxySession2.sessionId] })
      assert(Object.keys(respRevokeOther.sealdIds).length === 2) // revoke user2 and group
      assert(respRevokeOther.sealdIds[groupId] === 'ok')
      assert(respRevokeOther.sealdIds[user2AccountInfo.sealdId] === 'ok')
      assert(Object.keys(respRevokeOther.proxySessions).length === 1)
      assert(respRevokeOther.proxySessions[proxySession2.sessionId] === 'ok')

      // user2 cannot retrieve the session anymore
      await assert.rejects(sdk2.retrieveEncryptionSession({
        encryptedMessage,
        useCache: false,
        lookupProxyKey: false,
        lookupGroupKey: false
      }), /GO_NO_TOKEN_FOR_YOU_API — NO_TOKEN_FOR_YOU — Can't decipher this message — undefined on undefined/)

      // user1 revokes all. It can no longer retrieve it.
      const respRevokeAll = await es1SDK1.revoke()
      assert(Object.keys(respRevokeAll.sealdIds).length === 1)
      assert(respRevokeAll.sealdIds[user1AccountInfo.sealdId] === 'ok')
      assert(Object.keys(respRevokeAll.proxySessions).length === 0)

      // user1 cannot retrieve anymore
      await assert.rejects(sdk1.retrieveEncryptionSession({
        encryptedMessage,
        useCache: false,
        lookupProxyKey: false,
        lookupGroupKey: false
      }), /GO_NO_TOKEN_FOR_YOU_API — NO_TOKEN_FOR_YOU — Can't decipher this message — undefined on undefined/)

      // Create additional data for user1
      const es2SDK1 = await sdk1.createEncryptionSession({ sealdIds: [user1AccountInfo.sealdId] }, { useCache: false })
      const anotherMessage = 'nobody should read that!'
      const secondEncryptedMessage = await es2SDK1.encryptMessage(anotherMessage)
      const es3SDK1 = await sdk1.createEncryptionSession({ sealdIds: [user1AccountInfo.sealdId] }, { useCache: false })
      const es4SDK1 = await sdk1.createEncryptionSession({ sealdIds: [user1AccountInfo.sealdId] }, { useCache: false })

      // user1 can retrieveMultiple
      const encryptionSessions = await sdk1.retrieveMultipleEncryptionSessions(
        [{ sessionId: es2SDK1.sessionId }, { sessionId: es3SDK1.sessionId }, { sessionId: es4SDK1.sessionId }],
        { useCache: false, lookupProxyKey: false, lookupGroupKey: false })
      assert(encryptionSessions.length === 3)
      assert(encryptionSessions[0].sessionId === es2SDK1.sessionId)
      assert(encryptionSessions[1].sessionId === es3SDK1.sessionId)
      assert(encryptionSessions[2].sessionId === es4SDK1.sessionId)

      // user1 can renew its key, and still decrypt old messages
      const preparedRenewal = await sdk1.prepareRenew()
      // `preparedRenewal` Can be stored on SSKS as a new identity.
      // That way, a backup will be available is the renewKeys fail.

      await sdk1.renewKey({ preparedRenewal })
      const es2SDK1AfterRenew = await sdk1.retrieveEncryptionSession({
        sessionId: es2SDK1.sessionId,
        useCache: false,
        lookupProxyKey: false,
        lookupGroupKey: false
      })
      const decryptedMessageAfterRenew = await es2SDK1AfterRenew.decryptMessage(secondEncryptedMessage)
      assert(anotherMessage === decryptedMessageAfterRenew)

      // CONNECTORS https://docs.seald.io/en/sdk/guides/jwt.html#adding-a-userid

      // we can add a custom userId using a JWT
      const customConnectorJWTValue = 'user1-custom-id'
      const addConnectorJWT = await jwtBuilder.connectorJWT(customConnectorJWTValue)
      await sdk1.pushJwt(addConnectorJWT)

      // user1 can export its identity
      const exportIdentity = await sdk1.exportIdentity()

      // We can instantiate a new SealdSDK, import the exported identity
      const sdk1Exported = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, databasePath: 'sdk1Exported', databaseKey })
      await sdk1Exported.importIdentity(exportIdentity)

      // SDK with imported identity can decrypt
      const es2SDK1Exported = await sdk1Exported.retrieveEncryptionSession({ encryptedMessage: secondEncryptedMessage, useCache: false })
      const clearMessageExportedIdentity = await es2SDK1Exported.decryptMessage(secondEncryptedMessage)
      assert(anotherMessage === clearMessageExportedIdentity)

      // user1 can create sub identity
      const subIdentity = await sdk1.createSubIdentity({ deviceName: 'SUB-deviceName', shouldReencrypt: true })
      assert(isUUID(subIdentity.deviceId))

      // We can instantiate a new SealdSDK, import the sub-device identity
      const sdk1SubDevice = SealdSDK({ appId: testCredentials.appId, apiURL: testCredentials.apiURL, databasePath: 'sdk1SubDevice', databaseKey })
      await sdk1SubDevice.importIdentity(subIdentity.identity)

      // sub device can decrypt
      const es2SDK1SubDevice = await sdk1SubDevice.retrieveEncryptionSession({ encryptedMessage: secondEncryptedMessage, useCache: false })

      const clearMessageSubIdentity = await es2SDK1SubDevice.decryptMessage(secondEncryptedMessage)
      assert(anotherMessage === clearMessageSubIdentity)

      // Get and Check sigchain hash
      const user1LastSigchainHash = await sdk1.getSigchainHash({ sealdIds: [user1AccountInfo.sealdId] })
      assert(user1LastSigchainHash.position === 2)
      const user1FirstSigchainHash = await sdk2.getSigchainHash({ sealdIds: [user1AccountInfo.sealdId] }, { position: 0 })
      assert(user1FirstSigchainHash.position === 0)
      const lastHashCheck = await sdk2.checkSigchainHash({ sealdIds: [user1AccountInfo.sealdId] }, user1LastSigchainHash.hash)
      assert(lastHashCheck.position === 2)
      assert(lastHashCheck.lastPosition === 2)
      const firstHashCheck = await sdk1.checkSigchainHash({ sealdIds: [user1AccountInfo.sealdId] }, user1FirstSigchainHash.hash)
      assert(firstHashCheck.position === 0)
      assert(firstHashCheck.lastPosition === 2)
      await assert.rejects(
        sdk2.checkSigchainHash({ sealdIds: [user1AccountInfo.sealdId] }, user1FirstSigchainHash.hash, { position: 1 }),
        /User sigchain hash mismatch given one./
      )

      // Group TMR temporary keys

      // First, create a group to test on. sdk1 create a TMR temporary key to this group, sdk2 will join.
      const groupTMRName = 'group-TMR'
      const groupTMR = await sdk1.createGroup({ groupName: groupTMRName, members: { sealdIds: [user1AccountInfo.sealdId] }, admins: { sealdIds: [user1AccountInfo.sealdId] } })

      // WARNING: This should be a cryptographically random buffer of 64 bytes.
      const gTMRRawOverEncryptionKey = await sdk1.utils.generateB64EncodedSymKey()

      // We defined a two man rule recipient earlier. We will use it again.
      // The authentication factor is `tmrAuthFactor`.
      // Also we already have the TMR JWT associated with it: `tmrJWT.token`

      const gTMRCreated = await sdk1.createGroupTMRTemporaryKey(groupTMR.id, { authFactor: tmrAuthFactor, rawOverEncryptionKey: gTMRRawOverEncryptionKey, isAdmin: true })
      assert(gTMRCreated.authFactorType === 'EM')
      assert(gTMRCreated.isAdmin)
      assert(gTMRCreated.groupId === groupTMR.id)

      const gTMRList = await sdk1.listGroupTMRTemporaryKeys(groupTMR.id)
      assert(gTMRList.nbPage === 1)
      assert(gTMRList.results.length === 1)
      assert(gTMRList.results[0].id === gTMRCreated.id)
      assert(gTMRList.results[0].groupId === gTMRCreated.groupId)
      assert(gTMRList.results[0].isAdmin)

      const gTMRSearch = await sdk1.searchGroupTMRTemporaryKeys(tmrJWT.token)
      assert(gTMRSearch.nbPage === 1)
      assert(gTMRSearch.results.length === 1)
      assert(gTMRSearch.results[0].id === gTMRCreated.id)
      assert(gTMRSearch.results[0].groupId === gTMRCreated.groupId)
      assert(gTMRSearch.results[0].isAdmin)

      await sdk2.convertGroupTMRTemporaryKey(groupTMR.id, gTMRCreated.id, tmrJWT.token, gTMRRawOverEncryptionKey)
      await sdk1.deleteGroupTMRTemporaryKey(groupTMR.id, gTMRCreated.id)

      // Heartbeat can be used to check if proxies and firewalls are configured properly so that the app can reach Seald's servers.
      await sdk1.heartbeat()

      // close SDKs
      await sdk1.close()
      await sdk2.close()
      await sdk3.close()

      console.log('SDK tests success!')
      setHasFinishedSDK(true)
    } catch (error) {
      console.error('SDK tests FAILED')
      console.error(error)
      console.error(error.stack)
      setHasErrorSDK(error.toString())
      setHasFinishedSDK(true)
    }
  }

  const [hasStartedSDK, setHasStartedSDK] = useState(false)
  const [hasStartedSSKSTMR, setHasStartedSSKSTMR] = useState(false)
  const [hasStartedSSKSPassword, setHasStartedSSKSPassword] = useState(false)

  const [hasFinishedSDK, setHasFinishedSDK] = useState(false)
  const [hasFinishedSSKSTMR, setHasFinishedSSKSTMR] = useState(false)
  const [hasFinishedSSKSPassword, setHasFinishedSSKSPassword] = useState(false)

  const [hasErrorSDK, setHasErrorSDK] = useState('')
  const [hasErrorSSKSTMR, setHasErrorSSKSTMR] = useState('')
  const [hasErrorSSKSPassword, setHasErrorSSKSPassword] = useState('')

  const startTest = async () => {
    // The SealdSDK uses a local database. This database should be written to a permanent directory.
    // On react-native, the SealdSDK uses AsyncStorage for database.

    // This demo expects a clean database path to create it's own data, so we need to clean what previous runs left.
    // In a real app, it should never be done.
    await AsyncStorage.clear()

    // Seald uses JWT to manage licenses and identity.
    // JWTs should be generated by your backend, and sent to the user at signup.
    // The JWT secretId and secret can be generated from your administration dashboard. They should NEVER be on client side.
    // However, as this is a demo without a backend, we will use them on the frontend.
    // JWT documentation: https://docs.seald.io/en/sdk/guides/jwt.html
    // identity documentation: https://docs.seald.io/en/sdk/guides/4-identities.html
    const jwtBuilder = JwtBuilder(testCredentials.JWTSharedSecret, testCredentials.JWTSharedSecretId, testCredentials.appId)

    testSealdSsksTMR(jwtBuilder)
    testSealdSsksPassword(jwtBuilder)
    testSealdSDK(jwtBuilder)
  }

  useEffect(() => {
    startTest()
  }, [])

  return (
    <View
      style={{
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center'
      }}
    >
      <View>
        <Text>SDK tests:</Text>
        {(hasStartedSDK && !hasFinishedSDK) && (
          <Text>Running...</Text>
        )}
        {hasFinishedSDK && (
          hasErrorSDK
            ? (
            <Text accessibilityLabel={'testError'}>{hasErrorSDK}</Text>
              )
            : (
            <Text accessibilityLabel={'testError'}>SDK tests successful</Text>
              )
        )}
      </View>
      <View>
        <Text>SSKS Password tests:</Text>
        {(hasStartedSSKSPassword && !hasFinishedSSKSPassword) && (
          <Text>Running...</Text>
        )}
        {hasFinishedSSKSPassword && (
          hasErrorSSKSPassword
            ? (
            <Text accessibilityLabel={'testError'}>{hasErrorSSKSPassword}</Text>
              )
            : (
            <Text accessibilityLabel={'testError'}>SSKS Password tests successful</Text>
              )
        )}
      </View>
      <View>
        <Text>SSKS TMR tests:</Text>
        {(hasStartedSSKSTMR && !hasFinishedSSKSTMR) && (
          <Text>Running...</Text>
        )}
        {hasFinishedSSKSTMR && (
          hasErrorSSKSTMR
            ? (
            <Text accessibilityLabel={'testError'}>{hasErrorSSKSTMR}</Text>
              )
            : (
            <Text accessibilityLabel={'testError'}>SSKS TMR tests successful</Text>
              )
        )}
      </View>
    </View>
  )
}
