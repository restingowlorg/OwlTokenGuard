import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { decodeUnsafeJwtPayload } from "../src/jwt/JwtSigner";
import { Aes256GcmCipher } from "../src/ciphering/Aes256GcmCipher";
import { TEST_HMAC_SECRET, generateRsaKeyPair } from "./helpers/keys";

describe("TokenManager.generateAccessToken", () => {
  it("should issue an HS256 JWT with standard claims and no reference token", async () => {
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
    });

    const result = await manager.generateAccessToken({ sub: "user-1" });

    expect(result.token.split(".")).toHaveLength(3);
    expect("referenceToken" in result).toBe(false);

    const claims = decodeUnsafeJwtPayload(result.token);
    expect(claims.sub).toBe("user-1");
    expect(claims.jti).toBe(result.claims.jti);
  });

  it("should issue an RS256 JWT with asymmetric keys", async () => {
    const { privateKey } = generateRsaKeyPair();
    const manager = createTokenManager({
      algorithm: "RS256",
      signingKey: { type: "asymmetric", privateKey },
      expiresInSeconds: 3600,
    });

    const result = await manager.generateAccessToken({ sub: "user-2" });
    const claims = decodeUnsafeJwtPayload(result.token);
    expect(claims.sub).toBe("user-2");
  });

  it("should terminate previous session when previousSession is provided", async () => {
    const terminated: string[] = [];
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
      onSessionTerminate: async ({ jti }) => {
        terminated.push(jti);
      },
    });

    const first = await manager.generateAccessToken({ sub: "user-3" });
    await manager.generateAccessToken(
      { sub: "user-3" },
      { previousSession: first.claims },
    );

    expect(terminated).toContain(first.claims.jti);
  });

  it("should encrypt payload with AES-256-GCM when cipher is configured", async () => {
    const encryptionKey = Buffer.alloc(32, 7);
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
      payloadCipher: new Aes256GcmCipher(encryptionKey),
      refreshTokenEnabled: true,
      refreshTokenExpiresInSeconds: 3600,
    });

    const result = await manager.generateAccessToken({
      sub: "user-3",
      role: "admin",
    });
    const claims = decodeUnsafeJwtPayload(result.token);
    const refreshClaims = decodeUnsafeJwtPayload(result.refreshToken!);

    expect(claims.enc).toBeDefined();
    expect(claims.role).toBeUndefined();
    expect(result.refreshToken).toMatch(
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    );
    expect(refreshClaims.token_use).toBe("refresh");
    expect(refreshClaims.sub).toBe("user-3");
    expect(refreshClaims.jti).toBe(result.refreshClaims?.jti);
    expect(refreshClaims.jti).not.toBe(result.claims.jti);
  });

  it("should invoke onRefreshTokenIssued before returning tokens", async () => {
    const saved: Array<{
      refreshJti: string;
      accessJti: string;
      sub?: string;
      expiresAt: number;
    }> = [];

    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
      refreshTokenEnabled: true,
      refreshTokenExpiresInSeconds: 86400,
      onRefreshTokenIssued: async (context) => {
        saved.push({
          refreshJti: context.refreshClaims.jti,
          accessJti: context.accessClaims.jti,
          sub:
            typeof context.payload.sub === "string"
              ? context.payload.sub
              : undefined,
          expiresAt: context.expiresAt,
        });
      },
    });

    const result = await manager.generateAccessToken({ sub: "user-db" });

    expect(saved).toHaveLength(1);
    expect(saved[0].refreshJti).toBe(result.refreshClaims?.jti);
    expect(saved[0].accessJti).toBe(result.claims.jti);
    expect(saved[0].sub).toBe("user-db");
    expect(saved[0].expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("should fail issuance when onRefreshTokenIssued throws", async () => {
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
      refreshTokenEnabled: true,
      refreshTokenExpiresInSeconds: 86400,
      onRefreshTokenIssued: async () => {
        throw new Error("database unavailable");
      },
    });

    await expect(
      manager.generateAccessToken({ sub: "user-fail" }),
    ).rejects.toThrow(/Refresh token persistence failed/i);
  });

  it("should invoke onRefreshTokenIssued from generate compatibility wrapper", async () => {
    const saved: string[] = [];
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
      refreshTokenEnabled: true,
      refreshTokenExpiresInSeconds: 86400,
      onRefreshTokenIssued: async (context) => {
        saved.push(context.refreshClaims.jti);
      },
    });

    const result = await manager.generate({ sub: "user-generate" });

    expect(saved).toEqual([result.refreshClaims?.jti]);
    expect(result.referenceToken).toBeDefined();
  });

  it("should issue access and refresh tokens when refresh tokens are enabled", async () => {
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
      refreshTokenEnabled: true,
      refreshTokenExpiresInSeconds: 86400,
    });

    const result = await manager.generateAccessToken({ sub: "user-refresh" });
    const accessClaims = decodeUnsafeJwtPayload(result.token);
    const refreshClaims = decodeUnsafeJwtPayload(result.refreshToken!);

    expect(result.refreshToken).toBeDefined();
    expect(result.refreshClaims).toEqual(
      expect.objectContaining({ jti: refreshClaims.jti }),
    );
    expect(accessClaims.token_use).toBe("access");
    expect(refreshClaims.token_use).toBe("refresh");
    expect(accessClaims.jti).not.toBe(refreshClaims.jti);
  });
});

describe("TokenManager.generateReferenceToken", () => {
  it("should issue an opaque reference token without a JWT", () => {
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
    });

    const result = manager.generateReferenceToken({
      referenceEncoding: "base64url",
    });

    expect(result.referenceToken.length).toBeGreaterThan(0);
    expect(result.encoding).toBe("base64url");
    expect(result.entropyBits).toBeGreaterThanOrEqual(128);
    expect("token" in result).toBe(false);
  });
});

describe("TokenManager.generate (compatibility wrapper)", () => {
  it("should issue both access JWT and reference token", async () => {
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
    });

    const result = await manager.generate({ sub: "user-4" });

    expect(result.token.split(".")).toHaveLength(3);
    expect(result.referenceToken).toBeDefined();
    expect(result.claims.jti).toBeDefined();
  });
});
