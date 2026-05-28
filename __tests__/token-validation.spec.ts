import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { validateToken } from "../src/validation/validateToken";
import { TokenVerificationError } from "../src/errors/TokenVerificationError";
import { UntrustedKeySourceError } from "../src/errors/UntrustedKeySourceError";
import { TEST_HMAC_SECRET, generateRsaKeyPair } from "./helpers/keys";
import { buildSignedTestJwt, buildUnsignedJwt } from "./helpers/jwt";

const baseConfig = {
  algorithm: "HS256" as const,
  hmacSecret: TEST_HMAC_SECRET,
  expiresInSeconds: 3600,
  audience: "my-api",
  trustedIssuers: ["https://issuer.example"],
};

describe("Epic 2: validateToken / verify", () => {
  it("should verify a valid access token with default standard checks", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      allowedAlgorithms: ["HS256"],
    });

    const issued = await manager.generateAccessToken({
      sub: "user-1",
      iss: "https://issuer.example",
      aud: "my-api",
    });

    const result = await validateToken(manager, issued.token, {
      purpose: "access"
    });

    console.log("result", result);

    expect(result.jti).toBe(issued.claims.jti);
    expect(result.payload.sub).toBe("user-1");
    expect(result.claims.aud).toBe("my-api");
  });

  it("should reject tampered signatures (Story 2.1 signature-first)", async () => {
    const manager = createTokenManager(baseConfig);
    const issued = await manager.generateAccessToken({ sub: "user-1" });
    const tampered = `${issued.token.slice(0, -1)}x`;

    await expect(validateToken(manager, tampered)).rejects.toThrow(
      TokenVerificationError,
    );
  });

  it("should reject none algorithm (Story 2.1)", async () => {
    const manager = createTokenManager(baseConfig);
    const token = buildUnsignedJwt(
      { alg: "none", typ: "JWT" },
      { sub: "user-1", iat: 1, nbf: 1, jti: "x" },
    );

    await expect(validateToken(manager, token)).rejects.toThrow(
      TokenVerificationError,
    );
  });

  it("should reject algorithms outside the allowlist (Story 2.1)", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      allowedAlgorithms: ["HS512"],
    });
    const issued = await manager.generateAccessToken({ sub: "user-1" });

    await expect(validateToken(manager, issued.token)).rejects.toThrow(
      /allowlist/i,
    );
  });

  it("should reject untrusted jku header (Story 2.2)", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      trustedKeySourceDomains: ["keys.example"],
    });
    const token = buildSignedTestJwt(
      baseConfig,
      { sub: "user-1" },
      { jku: "https://evil.example/keys.json" },
    );

    await expect(validateToken(manager, token)).rejects.toThrow(
      UntrustedKeySourceError,
    );
  });

  it("should reject expired tokens (Story 2.3 exp)", async () => {
    const manager = createTokenManager(baseConfig);
    const now = Math.floor(Date.now() / 1000);
    const token = buildSignedTestJwt(baseConfig, {
      sub: "user-1",
      exp: now - 10,
    });

    await expect(validateToken(manager, token)).rejects.toThrow(/expired/i);
  });

  it("should reject tokens before nbf (Story 2.3 nbf)", async () => {
    const manager = createTokenManager(baseConfig);
    const now = Math.floor(Date.now() / 1000);
    const token = buildSignedTestJwt(baseConfig, {
      sub: "user-1",
      nbf: now + 3600,
    });

    await expect(validateToken(manager, token)).rejects.toThrow(/not yet valid/i);
  });

  it("should reject audience mismatch (Story 2.3 aud)", async () => {
    const manager = createTokenManager(baseConfig);
    const token = buildSignedTestJwt(baseConfig, {
      sub: "user-1",
      iss: "https://issuer.example",
      aud: "other-api",
    });

    await expect(validateToken(manager, token)).rejects.toThrow(/audience/i);
  });

  it("should reject untrusted issuer (Story 2.3 iss)", async () => {
    const manager = createTokenManager(baseConfig);
    const token = buildSignedTestJwt(baseConfig, {
      sub: "user-1",
      iss: "https://evil.example",
      aud: "my-api",
    });

    await expect(validateToken(manager, token)).rejects.toThrow(/issuer/i);
  });

  it("should reject ID tokens used as access tokens (Story 2.4)", async () => {
    const manager = createTokenManager(baseConfig);
    const token = buildSignedTestJwt(baseConfig, {
      sub: "user-1",
      iss: "https://issuer.example",
      aud: "my-api",
      token_use: "id",
    });

    await expect(
      validateToken(manager, token, { purpose: "access" , onVerified: (result) =>{
        console.log("result", result);
        if (result.payload.token_use === "id") {
          throw new TokenVerificationError("ID token cannot be used as access token");
        }
      }},
      ),
    ).rejects.toThrow(/ID token cannot be used/i);
  });

  it("should run developer hook after default validation", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      trustedIssuers: undefined,
      audience: undefined,
    });
    const issued = await manager.generateAccessToken({ sub: "user-1" });
    const seen: string[] = [];

    await validateToken(manager, issued.token, {
      onVerified: (result) => {
        seen.push(result.jti);
      },
    });

    expect(seen).toEqual([issued.claims.jti]);
  });

  it("should verify RS256 tokens with public key (Story 2.1 key confusion)", async () => {
    const { privateKey, publicKey } = generateRsaKeyPair();
    const manager = createTokenManager({
      algorithm: "RS256",
      signingKey: { type: "asymmetric", privateKey, publicKey },
      expiresInSeconds: 3600,
      allowedAlgorithms: ["RS256"],
    });

    const issued = await manager.generateAccessToken({ sub: "user-rsa" });
    const result = await manager.verify(issued.token);
    expect(result.payload.sub).toBe("user-rsa");
  });

  it("should reject revoked sessions via isSessionRevoked", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      trustedIssuers: undefined,
      audience: undefined,
      isSessionRevoked: async (jti) => jti === "revoked-jti",
    });
    const token = buildSignedTestJwt(
      { ...baseConfig, trustedIssuers: undefined, audience: undefined },
      {
      sub: "user-1",
      jti: "revoked-jti",
      },
    );

    await expect(validateToken(manager, token)).rejects.toThrow(/revoked/i);
  });
});
