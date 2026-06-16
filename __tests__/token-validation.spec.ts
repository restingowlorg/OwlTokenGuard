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

  it("should reject verification when no allowlist is configured (Story 2.1)", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      allowedAlgorithms: [],
    });
    const issued = await manager.generateAccessToken({ sub: "user-1" });

    await expect(validateToken(manager, issued.token)).rejects.toThrow(
      /Verification allowlist is required/i,
    );
  });

  it("should fall back to configured algorithm when allowedAlgorithms is omitted", async () => {
    const manager = createTokenManager(baseConfig);
    const issued = await manager.generateAccessToken({
      sub: "user-1",
      iss: "https://issuer.example",
      aud: "my-api",
    });

    const result = await validateToken(manager, issued.token);
    expect(result.payload.sub).toBe("user-1");
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

  it("should reject non-https jku and x5u headers (Story 2.2)", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      trustedKeySourceDomains: ["keys.example"],
    });
    const httpJku = buildSignedTestJwt(
      baseConfig,
      { sub: "user-1" },
      { jku: "http://keys.example/keys.json" },
    );
    const httpX5u = buildSignedTestJwt(
      baseConfig,
      { sub: "user-1" },
      { x5u: "http://keys.example/cert.pem" },
    );

    await expect(validateToken(manager, httpJku)).rejects.toThrow(/must use https/i);
    await expect(validateToken(manager, httpX5u)).rejects.toThrow(/must use https/i);
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

  it("should require exp and nbf for access token verification (Story 2.3)", async () => {
    const manager = createTokenManager(baseConfig);
    const withoutExp = buildSignedTestJwt(baseConfig, {
      sub: "user-1",
      exp: undefined,
    });
    const withoutNbf = buildSignedTestJwt(baseConfig, {
      sub: "user-1",
      nbf: undefined,
    });

    await expect(
      validateToken(manager, withoutExp, { purpose: "access" }),
    ).rejects.toThrow(/missing required exp claim/i);
    await expect(
      validateToken(manager, withoutNbf, { purpose: "access" }),
    ).rejects.toThrow(/missing required nbf claim/i);
  });

  it("should allow missing exp when temporal claims are not required", async () => {
    const manager = createTokenManager(baseConfig);
    const token = buildSignedTestJwt(baseConfig, {
      sub: "user-1",
      iss: "https://issuer.example",
      aud: "my-api",
      exp: undefined,
    });

    const result = await validateToken(manager, token, {
      requireTemporalClaims: false,
    });
    expect(result.payload.sub).toBe("user-1");
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
      validateToken(manager, token, { purpose: "access" }),
    ).rejects.toThrow(/ID token cannot be used/i);
  });

  it("should reject access verification when token type is missing (Story 2.4)", async () => {
    const manager = createTokenManager(baseConfig);
    const token = buildSignedTestJwt(
      baseConfig,
      {
        sub: "user-1",
        iss: "https://issuer.example",
        aud: "my-api",
        token_use: undefined,
      },
      { typ: "JWT" },
    );

    await expect(
      validateToken(manager, token, { purpose: "access" }),
    ).rejects.toThrow(/Token type is required when purpose is enforced/i);
  });

  it("should accept access verification when type is declared in header.typ", async () => {
    const manager = createTokenManager(baseConfig);
    const token = buildSignedTestJwt(
      baseConfig,
      {
        sub: "user-1",
        iss: "https://issuer.example",
        aud: "my-api",
        token_use: undefined,
      },
      { typ: "access" },
    );

    const result = await validateToken(manager, token, { purpose: "access" });
    expect(result.payload.sub).toBe("user-1");
  });

  it("should reject access verification when header.typ declares id", async () => {
    const manager = createTokenManager(baseConfig);
    const token = buildSignedTestJwt(
      baseConfig,
      {
        sub: "user-1",
        iss: "https://issuer.example",
        aud: "my-api",
        token_use: undefined,
      },
      { typ: "id" },
    );

    await expect(
      validateToken(manager, token, { purpose: "access" }),
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
      isSessionRevoked: async ({ jti }) => jti === "revoked-jti",
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

  it("should reject tokens issued before getTokensInvalidBefore cutoff", async () => {
    const invalidBeforeBySub = new Map<string, number>([["user-cutoff", 2_000_000_000]]);

    const manager = createTokenManager({
      ...baseConfig,
      trustedIssuers: undefined,
      audience: undefined,
      getTokensInvalidBefore: async (sub) => invalidBeforeBySub.get(sub),
    });

    const token = buildSignedTestJwt(
      { ...baseConfig, trustedIssuers: undefined, audience: undefined },
      {
        sub: "user-cutoff",
        jti: "older-token",
        iat: 1_000_000_000,
        nbf: 1_000_000_000,
        exp: 9_999_999_999,
      },
    );

    await expect(validateToken(manager, token)).rejects.toThrow(/invalidation cutoff/i);
  });

  it("should reject tokens via isSessionRevoked using iat-aware policy", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      trustedIssuers: undefined,
      audience: undefined,
      isSessionRevoked: async ({ iat, sub }) =>
        sub === "user-ts" && iat < 2_000_000_000,
    });

    const token = buildSignedTestJwt(
      { ...baseConfig, trustedIssuers: undefined, audience: undefined },
      {
        sub: "user-ts",
        jti: "old-session",
        iat: 1_000_000_000,
        nbf: 1_000_000_000,
        exp: 9_999_999_999,
      },
    );

    await expect(validateToken(manager, token)).rejects.toThrow(/revoked/i);
  });

  it("should stamp reauth_at when issuing with reauthAt option", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      trustedIssuers: undefined,
      audience: undefined,
      refreshTokenEnabled: true,
      refreshTokenExpiresInSeconds: 86400,
    });

    const reauthAt = 2_000_000_000;
    const issued = await manager.generateAccessToken({ sub: "user-fresh" }, { reauthAt });

    const access = await manager.verify(issued.token, { purpose: "access" });
    expect(access.claims.reauth_at).toBe(reauthAt);
    expect(access.payload.reauth_at).toBe(reauthAt);

    const refresh = await manager.verify(issued.refreshToken!, {
      purpose: "refresh",
    });
    expect(refresh.claims.reauth_at).toBe(reauthAt);
  });

  it("should reject tokens with stale reauth_at via getMinimumReauthAt", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      trustedIssuers: undefined,
      audience: undefined,
      getMinimumReauthAt: async (sub) =>
        sub === "user-stale" ? 2_000_000_000 : undefined,
    });

    const token = buildSignedTestJwt(
      { ...baseConfig, trustedIssuers: undefined, audience: undefined },
      {
        sub: "user-stale",
        jti: "stale-reauth",
        reauth_at: 1_000_000_000,
        token_use: "access",
      },
    );

    await expect(validateToken(manager, token)).rejects.toThrow(/stale/i);
  });

  it("should reject tokens missing reauth_at when requireReauthAtClaim is true", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      trustedIssuers: undefined,
      audience: undefined,
      requireReauthAtClaim: true,
    });

    const token = buildSignedTestJwt(
      { ...baseConfig, trustedIssuers: undefined, audience: undefined },
      {
        sub: "user-missing",
        jti: "missing-reauth",
        token_use: "access",
      },
    );

    await expect(validateToken(manager, token)).rejects.toThrow(/reauth_at/i);
  });

  it("should enforce minimumReauthAt via verify options", async () => {
    const manager = createTokenManager({
      ...baseConfig,
      trustedIssuers: undefined,
      audience: undefined,
    });

    const token = buildSignedTestJwt(
      { ...baseConfig, trustedIssuers: undefined, audience: undefined },
      {
        sub: "user-override",
        jti: "override-reauth",
        reauth_at: 1_500_000_000,
        token_use: "access",
      },
    );

    await expect(
      manager.verify(token, { minimumReauthAt: 2_000_000_000 }),
    ).rejects.toThrow(/stale/i);
  });
});
