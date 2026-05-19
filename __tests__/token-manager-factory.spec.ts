import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { TokenManager } from "../src/core/TokenManager";
import { defaults } from "../src/config/defaults";

describe("createTokenManager", () => {
  it("should return a TokenManager instance", () => {
    const manager = createTokenManager();
    expect(manager).toBeInstanceOf(TokenManager);
  });

  it("should accept an empty config", () => {
    const manager = createTokenManager({});
    expect(manager.config).toEqual({});
  });

  it("should expose defaults for epic 1 configuration", () => {
    expect(defaults.algorithm).toBe("RS256");
    expect(defaults.opaqueEntropyBits).toBe(128);
    expect(defaults.minHmacSecretLength).toBe(64);
  });
});
