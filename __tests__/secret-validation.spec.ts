import { SecretValidator } from "../src/security/SecretValidator";
import { SecurityConfigurationError } from "../src/errors/SecurityConfigurationError";
import { TEST_HMAC_SECRET } from "./helpers/keys";

describe("SecretValidator", () => {
  it("should reject HMAC secrets shorter than 64 characters", () => {
    expect(() => SecretValidator.validateHmacSecret("short-secret")).toThrow(
      SecurityConfigurationError,
    );
  });

  it("should reject predictable secrets even when length is sufficient", () => {
    expect(() =>
      SecretValidator.validateHmacSecret("password".repeat(8)),
    ).toThrow(SecurityConfigurationError);
  });

  it("should accept high-entropy secrets of at least 64 characters", () => {
    expect(() =>
      SecretValidator.validateHmacSecret(TEST_HMAC_SECRET),
    ).not.toThrow();
  });

  it("should expose a direct high-entropy assertion helper", () => {
    expect(() =>
      SecretValidator.assertHighEntropy(TEST_HMAC_SECRET),
    ).not.toThrow();
    expect(() => SecretValidator.assertHighEntropy("a".repeat(64))).toThrow(
      SecurityConfigurationError,
    );
  });
});
