import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { decodeJwtPayload } from "../src/jwt/JwtSigner";
import { TEST_HMAC_SECRET, generateRsaKeyPair } from "./helpers/keys";

/**
 * Integration-style tests mirroring documented usage:
 *
 *   createTokenManager({ algorithm, hmacSecret | signingKey })
 *   manager.generate(payload, { previousToken })
 */
describe("generate token (usage)", () => {
  describe("HS256 symmetric", () => {
    it("should generate a JWT, reference token, and standard claims", async () => {
      const terminatedJtis: string[] = [];

      const manager = createTokenManager({
        algorithm: "HS256",
        hmacSecret: TEST_HMAC_SECRET,
        onSessionTerminate: async ({ jti }) => {
          terminatedJtis.push(jti);
        },
      });

      const first = await manager.generate(
        { sub: "user-123", role: "admin" },
      );

      console.log(first);

      expect(first.token).toMatch(
        /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
      );
      expect(first.referenceToken).toBeDefined();
      expect(first.claims.iat).toEqual(expect.any(Number));
      expect(first.claims.nbf).toEqual(expect.any(Number));
      expect(first.claims.jti).toEqual(expect.any(String));

      const decodedFirst = decodeJwtPayload(first.token);
      expect(decodedFirst.sub).toBe("user-123");
      expect(decodedFirst.role).toBe("admin");
      expect(decodedFirst.jti).toBe(first.claims.jti);

      const second = await manager.generate(
        { sub: "user-123", role: "admin" },
        { previousToken: first.token },
      );

      console.log(second);

      expect(second.token).not.toBe(first.token);
      expect(second.claims.jti).not.toBe(first.claims.jti);
      expect(terminatedJtis).toContain(first.claims.jti);
    });
  });

  describe("RS256 asymmetric (preferred default)", () => {
    it("should generate a signed JWT with an RSA private key", async () => {
      const { privateKey } = generateRsaKeyPair();

      const manager = createTokenManager({
        algorithm: "RS256",
        signingKey: { type: "asymmetric", privateKey },
      });

      const { token, referenceToken, claims } = await manager.generate({
        sub: "user-456",
        role: "viewer",
      });

      expect(token.split(".")).toHaveLength(3);
      expect(referenceToken).toBeTruthy();

      const payload = decodeJwtPayload(token);
      expect(payload.sub).toBe("user-456");
      expect(payload.role).toBe("viewer");
      expect(payload.jti).toBe(claims.jti);
      expect(payload.iat).toBe(claims.iat);
      expect(payload.nbf).toBe(claims.nbf);
    });
  });

  describe("session rotation", () => {
    it("should issue a new token on every generate call", async () => {
      const manager = createTokenManager({
        algorithm: "HS256",
        hmacSecret: TEST_HMAC_SECRET,
      });

      const a = await manager.generate({ sub: "user-789" });
      const b = await manager.generate({ sub: "user-789" });

      expect(a.token).not.toBe(b.token);
      expect(a.referenceToken).not.toBe(b.referenceToken);
      expect(a.claims.jti).not.toBe(b.claims.jti);
    });
  });
});
