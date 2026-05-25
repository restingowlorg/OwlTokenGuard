import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { TokenManager } from "../src/core/TokenManager";
import { defaults } from "../src/config/defaults";

describe("createTokenManager", () => {
  it("should return a TokenManager instance", () => {
    const manager = createTokenManager({
      expiresInSeconds: 3600,
    });
    expect(manager).toBeInstanceOf(TokenManager);
  });

  it("should validate config before returning an instance", () => {
    expect(() =>
      createTokenManager({
        algorithm: "none" as never,
        expiresInSeconds: 3600,
      }),
    ).toThrow();
  });

  it("should accept config and expose it on the instance", () => {
    const manager = createTokenManager({
      expiresInSeconds: 3600,
    });
    expect(manager.config.expiresInSeconds).toBe(3600);
  });

  it("should expose defaults for epic 1 configuration", () => {
    expect(defaults.algorithm).toBe("RS256");
    expect(defaults.opaqueEntropyBits).toBe(128);
    expect(defaults.minHmacSecretLength).toBe(64);
  });
});
