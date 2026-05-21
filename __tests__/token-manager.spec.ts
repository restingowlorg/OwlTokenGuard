import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { decodeJwtPayload } from "../src/jwt/JwtSigner";
import { Aes256GcmCipher } from "../src/ciphering/Aes256GcmCipher";
import { TEST_HMAC_SECRET, generateRsaKeyPair } from "./helpers/keys";

describe("TokenManager.generate", () => {
  it("should issue an HS256 JWT with standard claims", async () => {
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
    });

    const result = await manager.generate({ sub: "user-1" });

    expect(result.token.split(".")).toHaveLength(3);
    expect(result.referenceToken).toBeDefined();

    const claims = decodeJwtPayload(result.token);
    expect(claims.sub).toBe("user-1");
    expect(claims.jti).toBe(result.claims.jti);
    expect(claims.iat).toBe(result.claims.iat);
    expect(claims.nbf).toBe(result.claims.nbf);
  });

  it("should issue an RS256 JWT with asymmetric keys", async () => {
    const { privateKey } = generateRsaKeyPair();
    const manager = createTokenManager({
      algorithm: "RS256",
      signingKey: { type: "asymmetric", privateKey },
    });

    const result = await manager.generate({ sub: "user-2" });
    const claims = decodeJwtPayload(result.token);
    expect(claims.sub).toBe("user-2");
    expect(typeof claims.jti).toBe("string");
  });

  it("should terminate previous session when previousToken is provided", async () => {
    const terminated: string[] = [];
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      onSessionTerminate: async ({ jti }) => {
        terminated.push(jti);
      },
    });

    const first = await manager.generate({ sub: "user-3" });
    await manager.generate(
      { sub: "user-3" },
      { previousToken: first.token },
    );

    expect(terminated).toContain(first.claims.jti);
  });

  it("should encrypt payload with AES-256-GCM when cipher is configured", async () => {
    const encryptionKey = Buffer.alloc(32, 7);
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      payloadCipher: new Aes256GcmCipher(encryptionKey),
    });

    const result = await manager.generate({ role: "admin" });
    const claims = decodeJwtPayload(result.token);

    expect(claims.enc).toBeDefined();
    expect(claims.role).toBeUndefined();
    expect((claims.enc as { authTag: string }).authTag).toBeDefined();
  });
});
