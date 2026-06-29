import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { TokenManager } from "../src/core/TokenManager";
import { defaults } from "../src/config/defaults";
import { SecurityConfigurationError } from "../src/errors/SecurityConfigurationError";
import { requiredTestHooks } from "./helpers/config";
import {
  TEST_HMAC_SECRET,
  generateEcKeyPair,
  generateRsaKeyPair,
} from "./helpers/keys";

describe("createTokenManager", () => {
  it("should return a TokenManager instance", () => {
    const manager = createTokenManager({
      ...requiredTestHooks,
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
    });
    expect(manager).toBeInstanceOf(TokenManager);
  });

  it("should validate config before returning an instance", () => {
    expect(() =>
      createTokenManager({
        ...requiredTestHooks,
        algorithm: "none" as never,
        expiresInSeconds: 3600,
      }),
    ).toThrow();
  });

  it("should accept config and expose it on the instance", () => {
    const manager = createTokenManager({
      ...requiredTestHooks,
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 3600,
    });
    expect(manager.config.expiresInSeconds).toBe(3600);
  });

  it("should expose normalized default algorithm and allowlist on the instance", () => {
    const keys = generateRsaKeyPair();
    const manager = createTokenManager({
      ...requiredTestHooks,
      signingKey: {
        type: "asymmetric",
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
      },
      expiresInSeconds: 3600,
    });

    expect(manager.config.algorithm).toBe("RS256");
    expect(manager.config.allowedAlgorithms).toEqual(["RS256"]);
  });

  it("should expose defaults for epic 1 configuration", () => {
    expect(defaults.algorithm).toBe("RS256");
    expect(defaults.opaqueEntropyBits).toBe(128);
    expect(defaults.minHmacSecretLength).toBe(64);
  });

  it("should reject default RS256 config when asymmetric keys are missing", () => {
    expect(() =>
      createTokenManager({
        ...requiredTestHooks,
        expiresInSeconds: 3600,
      }),
    ).toThrow(SecurityConfigurationError);
  });

  it("should reject HS256 config when HMAC secret is missing", () => {
    expect(() =>
      createTokenManager({
        ...requiredTestHooks,
        algorithm: "HS256",
        expiresInSeconds: 3600,
      }),
    ).toThrow(/HMAC secret is required/i);
  });

  it("should reject RS256 config when private key is missing", () => {
    const keys = generateRsaKeyPair();

    expect(() =>
      createTokenManager({
        ...requiredTestHooks,
        algorithm: "RS256",
        signingKey: {
          type: "asymmetric",
          publicKey: keys.publicKey,
        } as never,
        expiresInSeconds: 3600,
      }),
    ).toThrow(/Invalid private key PEM/i);
  });

  it("should reject RS256 config when public key is missing", () => {
    const keys = generateRsaKeyPair();

    expect(() =>
      createTokenManager({
        ...requiredTestHooks,
        algorithm: "RS256",
        signingKey: {
          type: "asymmetric",
          privateKey: keys.privateKey,
        } as never,
        expiresInSeconds: 3600,
      }),
    ).toThrow(/Public key is required/i);
  });

  it("should reject ES256 config when public key is missing", () => {
    const keys = generateEcKeyPair();

    expect(() =>
      createTokenManager({
        ...requiredTestHooks,
        algorithm: "ES256",
        signingKey: {
          type: "asymmetric",
          privateKey: keys.privateKey,
        } as never,
        expiresInSeconds: 3600,
      }),
    ).toThrow(/Public key is required/i);
  });

  it("should reject invalid asymmetric public key PEM at startup", () => {
    const keys = generateRsaKeyPair();

    expect(() =>
      createTokenManager({
        ...requiredTestHooks,
        algorithm: "RS256",
        signingKey: {
          type: "asymmetric",
          privateKey: keys.privateKey,
          publicKey: "not-a-public-key",
        },
        expiresInSeconds: 3600,
      }),
    ).toThrow(/Invalid public key PEM/i);
  });

  it("should reject an empty configured issuer", () => {
    expect(() =>
      createTokenManager({
        ...requiredTestHooks,
        algorithm: "HS256",
        hmacSecret: TEST_HMAC_SECRET,
        expiresInSeconds: 3600,
        issuer: " ",
      }),
    ).toThrow(/issuer must be a non-empty string/i);
  });

  it("should reject an empty configured audience list", () => {
    expect(() =>
      createTokenManager({
        ...requiredTestHooks,
        algorithm: "HS256",
        hmacSecret: TEST_HMAC_SECRET,
        expiresInSeconds: 3600,
        audience: [],
      }),
    ).toThrow(/audience must be a non-empty string/i);
  });

  it.each([
    ["onSessionTerminate", undefined],
    ["onSessionTerminate", "not-a-function"],
    ["onRefreshTokenIssued", "not-a-function"],
    ["consumeRefreshToken", "not-a-function"],
    ["getTokensInvalidBefore", "not-a-function"],
    ["getMinimumReauthAt", "not-a-function"],
    ["isSessionRevoked", "not-a-function"],
  ])("should reject invalid callback field %s", (fieldName, value) => {
    expect(() =>
      createTokenManager({
        ...requiredTestHooks,
        [fieldName]: value,
        algorithm: "HS256",
        hmacSecret: TEST_HMAC_SECRET,
        expiresInSeconds: 3600,
      }),
    ).toThrow(new RegExp(`${fieldName} must be a function`, "i"));
  });

  it.each([0, -1, NaN, Infinity, 1.5])(
    "should reject invalid expiresInSeconds at startup (%p)",
    (expiresInSeconds) => {
      expect(() =>
        createTokenManager({
          ...requiredTestHooks,
          algorithm: "HS256",
          hmacSecret: TEST_HMAC_SECRET,
          expiresInSeconds,
        }),
      ).toThrow(/expiresInSeconds must be a positive integer/i);
    },
  );

  it.each([0, -3600])(
    "should reject invalid refreshTokenExpiresInSeconds when refresh is enabled (%p)",
    (refreshTokenExpiresInSeconds) => {
      expect(() =>
        createTokenManager({
          ...requiredTestHooks,
          algorithm: "HS256",
          hmacSecret: TEST_HMAC_SECRET,
          expiresInSeconds: 3600,
          refreshTokenEnabled: true,
          refreshTokenExpiresInSeconds,
        }),
      ).toThrow(/refreshTokenExpiresInSeconds must be a positive integer/i);
    },
  );
});
