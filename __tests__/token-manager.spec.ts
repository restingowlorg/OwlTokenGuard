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
    });

    const result = await manager.generateAccessToken({ role: "admin" });
    const claims = decodeUnsafeJwtPayload(result.token);

    expect(claims.enc).toBeDefined();
    expect(claims.role).toBeUndefined();
  });
});

describe("TokenManager.generateReferenceToken", () => {
  it("should issue an opaque reference token without a JWT", () => {
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
    });

    const result = manager.generateReferenceToken({ referenceEncoding: "base64url" });

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
