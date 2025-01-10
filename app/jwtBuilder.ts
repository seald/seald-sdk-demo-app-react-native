import * as crypto from 'crypto'
import JWT from 'expo-jwt'
import { SupportedAlgorithms } from 'expo-jwt/dist/types/algorithms'

export interface JWTBuilder {
  signupJWT (): Promise<string>,

  connectorJWT (customUserId: string): Promise<string>
}

export const JwtBuilder = (
  JWTSharedSecret: string,
  JWTSharedSecretId: string,
  appId: string): JWTBuilder => {
  const jwtPermission = {
    all: -1,
    anonymousFindKey: '1',
    anonymousFindSigchain: '2',
    joinTeam: '3',
    addConnector: '4'
  }
  return {
    signupJWT: async () => {
      const random = crypto.randomBytes(16).toString('hex')

      const payload = {
        iss: JWTSharedSecretId,
        jti: random,
        iat: Math.floor(Date.now() / 1000),
        join_team: true,
        scopes: jwtPermission.joinTeam
      }

      return JWT.encode(payload, JWTSharedSecret, { algorithm: SupportedAlgorithms.HS256 })
    },
    connectorJWT: async (customUserId: string) => {
      const random = crypto.randomBytes(16).toString('hex')
      const payload = {
        iss: JWTSharedSecretId,
        jti: random,
        iat: Math.floor(Date.now() / 1000),
        connector_add: {
          value: `${customUserId}@${appId}`,
          type: 'AP'
        },
        scopes: jwtPermission.addConnector
      }
      return JWT.encode(payload, JWTSharedSecret, { algorithm: SupportedAlgorithms.HS256 })
    }
  }
}
