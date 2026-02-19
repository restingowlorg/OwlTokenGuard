// __tests__/createCryptoLibrary.test.ts
import crypto from "crypto";
import { createCryptoLibrary } from "../../src";
import { CryptoManager } from "../../src/manager/CryptoManager";
import { InsecureConfigurationError } from "../../src/errors/InsecureConfigurationError";
import { DEFAULTS } from "../../src/configs/defaults";

describe("createCryptoLibrary", () => {
  it("should return a CryptoManager instance", () => {
    const lib = createCryptoLibrary();
    expect(lib).toBeInstanceOf(CryptoManager);
  });

  it("should use provided masterKey if valid", () => {
    const key = crypto.randomBytes(DEFAULTS.KEY_LENGTH);
    const lib = createCryptoLibrary({ masterKey: key });
    expect(lib).toBeInstanceOf(CryptoManager);
    // Optionally, check that adapter received the same key
    expect((lib as any).encryption.adapter.key).toEqual(key);
  });

  it("should throw InsecureConfigurationError if masterKey length is invalid", () => {
    const shortKey = crypto.randomBytes(16); // less than 32 bytes
    expect(() => createCryptoLibrary({ masterKey: shortKey })).toThrow(
      InsecureConfigurationError,
    );
  });

  it("should generate a random 32-byte key if masterKey is not provided", () => {
    const lib = createCryptoLibrary();
    const adapterKey = (lib as any).encryption.adapter.key;
    expect(adapterKey).toHaveLength(DEFAULTS.KEY_LENGTH);
  });
});
