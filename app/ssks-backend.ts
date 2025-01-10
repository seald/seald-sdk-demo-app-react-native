import type { FetchFunction, TmrAuthFactor } from '@seald-io/sdk/lib/types'

export type SSKSBackendType = {
  challengeSend(userId: string, authFactor: { type: string, value: string }, opts?: {
    createUser?: boolean
    forceAuth?: boolean
  }): Promise<{ sessionId: string, mustAuthenticate: boolean }>
}

export default (keyStorageURL: string, fetch: FetchFunction, appId: string, appKey: string) => ({
  async challengeSend (userId: string, authFactor: TmrAuthFactor, { createUser = false, forceAuth = false, fakeOtp = false } = {}): Promise<{ sessionId: string, mustAuthenticate: boolean }> {
    const url = new URL('/tmr/back/challenge_send/', keyStorageURL).href
    const res = await fetch(
      url,
      {
        method: 'POST',
        credentials: 'omit',
        headers: {
          'Content-Type': 'application/json',
          'X-SEALD-APPID': appId,
          'X-SEALD-APIKEY': appKey
        },
        body: JSON.stringify({
          user_id: userId,
          auth_factor: authFactor,
          create_user: createUser,
          force_auth: forceAuth,
          fake_otp: fakeOtp,
          template: '<html><body>TEST CHALLENGE EMAIL</body></html>'
        })
      }
    )
    if (!res.ok) {
      const resText = await res.text()
      throw new Error(`SSKSBackend createUser failed: ${res.status} ${resText}`)
    }
    const { session_id: sessionId, must_authenticate: mustAuthenticate } = await res.json()
    return { sessionId, mustAuthenticate }
  }
})
