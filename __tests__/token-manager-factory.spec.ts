import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { TokenManager } from "../src/core/TokenManager";
import { defaults } from "../src/config/defaults";
import { requiredTestHooks } from "./helpers/config";

describe("createTokenManager", () => {
  it("should return a TokenManager instance", () => {
    const manager = createTokenManager({
      ...requiredTestHooks,
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
      expiresInSeconds: 3600,
    });
    expect(manager.config.expiresInSeconds).toBe(3600);
  });

  it("should expose normalized default algorithm and allowlist on the instance", () => {
    const manager = createTokenManager({
      ...requiredTestHooks,
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

  it.each([0, -1, NaN, Infinity, 1.5])(
    "should reject invalid expiresInSeconds at startup (%p)",
    (expiresInSeconds) => {
      expect(() =>
        createTokenManager({
          ...requiredTestHooks,
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
          expiresInSeconds: 3600,
          refreshTokenEnabled: true,
          refreshTokenExpiresInSeconds,
        }),
      ).toThrow(/refreshTokenExpiresInSeconds must be a positive integer/i);
    },
  );
});
