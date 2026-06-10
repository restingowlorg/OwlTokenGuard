import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { decodeUnsafeJwtPayload } from "../src/jwt/JwtSigner";
import { TEST_HMAC_SECRET, generateRsaKeyPair } from "./helpers/keys";

/**
 * Integration-style tests mirroring documented usage:
 *
 *   createTokenManager({ algorithm, hmacSecret | signingKey })
 *   manager.generateAccessToken(payload, { previousSession: first.claims })
 *   manager.generate(payload) // compatibility: JWT + reference
 */
describe("generate token (usage)", () => {
  describe("HS256 symmetric", () => {
    it("should generate a JWT access token with standard claims", async () => {
      const terminatedJtis: string[] = [];

      const manager = createTokenManager({
        algorithm: "HS256",
        hmacSecret: TEST_HMAC_SECRET,
        expiresInSeconds: 3600,
        refreshTokenEnabled: true,
        refreshTokenExpiresInSeconds: 86400,
        onSessionTerminate: async ({ jti }) => {
          terminatedJtis.push(jti);
        },
      });

      const first = await manager.generateAccessToken(
        { sub: "user-123", role: "admin" },
      );

      expect(first.token).toMatch(
        /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
      );
      expect(first.refreshToken).toMatch(
        /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
      );
      expect("referenceToken" in first).toBe(false);
      expect(first.claims.iat).toEqual(expect.any(Number));
      expect(first.claims.nbf).toEqual(expect.any(Number));
      expect(first.claims.jti).toEqual(expect.any(String));
      expect(first.refreshClaims?.jti).toEqual(expect.any(String));

      const decodedFirst = decodeUnsafeJwtPayload(first.token);
      const decodedRefresh = decodeUnsafeJwtPayload(first.refreshToken!);
      expect(decodedFirst.sub).toBe("user-123");
      expect(decodedFirst.role).toBe("admin");
      expect(decodedFirst.jti).toBe(first.claims.jti);
      expect(decodedFirst.token_use).toBe("access");
      expect(decodedRefresh.token_use).toBe("refresh");
      expect(decodedRefresh.sub).toBe("user-123");
      expect(decodedRefresh.jti).toBe(first.refreshClaims?.jti);

      const second = await manager.generateAccessToken(
        { sub: "user-123", role: "admin" },
        { previousSession: first.claims },
      );

      expect(second.token).not.toBe(first.token);
      expect(second.refreshToken).not.toBe(first.refreshToken);
      expect(second.claims.jti).not.toBe(first.claims.jti);
      expect(second.refreshClaims?.jti).not.toBe(first.refreshClaims?.jti);
      expect(terminatedJtis).toContain(first.claims.jti);
    });
  });

  describe("RS256 asymmetric (preferred default)", () => {
    it("should generate a signed JWT with an RSA private key", async () => {
      const { privateKey } = generateRsaKeyPair();

      const manager = createTokenManager({
        algorithm: "RS256",
        signingKey: { type: "asymmetric", privateKey },
        expiresInSeconds: 3600,
      });

      const { token, referenceToken, claims } = await manager.generate({
        sub: "user-456",
        role: "viewer",
      });

      expect(token.split(".")).toHaveLength(3);
      expect(referenceToken).toBeTruthy();

      const payload = decodeUnsafeJwtPayload(token);
      expect(payload.sub).toBe("user-456");
      expect(payload.role).toBe("viewer");
      expect(payload.jti).toBe(claims.jti);
      expect(payload.iat).toBe(claims.iat);
      expect(payload.nbf).toBe(claims.nbf);
    });
  });

  describe("session rotation", () => {
    it("should issue a new access and refresh token on every generateAccessToken call", async () => {
      const DummyCacheOrDatabase: string[] = [];
      const manager = createTokenManager({
        algorithm: "HS256",
        hmacSecret: TEST_HMAC_SECRET,
        expiresInSeconds: 3600,
        refreshTokenEnabled: true,
        refreshTokenExpiresInSeconds: 86400,
        onRefreshTokenIssued: async ({ refreshClaims }) => {
          /**
           * apply database or chashes to save refresh token jti for later verification
           * every times if generateded a refresh token always call this callback to save the refresh token jti for later verification
           */
          DummyCacheOrDatabase.push(refreshClaims.jti);
        },
      });

      const a = await manager.generateAccessToken({ sub: "user-789" });
      const b = await manager.generateAccessToken(
        { sub: "user-789" },
        { previousSession: a.claims },
      );

      expect(a.token).not.toBe(b.token);
      expect(a.refreshToken).not.toBe(b.refreshToken);
      expect(a.claims.jti).not.toBe(b.claims.jti);
      expect(a.refreshClaims?.jti).not.toBe(b.refreshClaims?.jti);
      expect(DummyCacheOrDatabase).toContain(a.refreshClaims?.jti);
      expect(DummyCacheOrDatabase).toContain(b.refreshClaims?.jti);
    });

    it("should issue both tokens via generate compatibility wrapper", async () => {
      const manager = createTokenManager({
        algorithm: "HS256",
        hmacSecret: TEST_HMAC_SECRET,
        expiresInSeconds: 3600,
      });

      const a = await manager.generate({ sub: "user-789" });
      const b = await manager.generate({ sub: "user-789" });

      expect(a.token).not.toBe(b.token);
      expect(a.referenceToken).not.toBe(b.referenceToken);
    });
  });

  describe("refresh tokens", () => {
    it("should return access and refresh tokens from generate when enabled", async () => {
      const manager = createTokenManager({
        algorithm: "HS256",
        hmacSecret: TEST_HMAC_SECRET,
        expiresInSeconds: 3600,
        refreshTokenEnabled: true,
        refreshTokenExpiresInSeconds: 86400,
      });

      const result = await manager.generate({ sub: "user-refresh" });

      expect(result.token.split(".")).toHaveLength(3);
      expect(result.refreshToken?.split(".")).toHaveLength(3);
      expect(result.referenceToken).toBeTruthy();

      const access = decodeUnsafeJwtPayload(result.token);
      const refresh = decodeUnsafeJwtPayload(result.refreshToken!);
      expect(access.token_use).toBe("access");
      expect(refresh.token_use).toBe("refresh");
    });
  });
});
