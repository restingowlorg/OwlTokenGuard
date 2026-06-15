import { createTokenManager } from "../../src/factories/TokenManagerFactory";
import type { TokenManager } from "../../src/core/TokenManager";
import { TEST_HMAC_SECRET } from "../helpers/keys";
import type { SessionStore } from "./sessionStore";

/**
 * Full TokenManager configuration used by the showcase API.
 * Wire your own persistence hooks by swapping SessionStore for a real DB layer.
 */
export function createShowcaseTokenManager(
  sessionStore: SessionStore,
): TokenManager {
  return createTokenManager({
    algorithm: "HS256",
    hmacSecret: TEST_HMAC_SECRET,
    expiresInSeconds: 900,
    refreshTokenEnabled: true,
    refreshTokenExpiresInSeconds: 604800,
    debug: false,
    onRefreshTokenIssued: async ({ refreshClaims }) => {
      sessionStore.saveRefreshToken(refreshClaims.jti);
    },
    consumeRefreshToken: async ({ jti }) => {
      return sessionStore.consumeRefreshToken(jti);
    },
    onSessionTerminate: async ({ jti }) => {
      await sessionStore.terminateSession(jti);
    },
    isSessionRevoked: async (jti) => {
      return sessionStore.isSessionRevoked(jti);
    },
  });
}
