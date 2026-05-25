import { defaults } from "../config/defaults";
import { SecurityConfigurationError } from "../errors/SecurityConfigurationError";
import { EntropyValidator } from "../utils/EntropyValidator";
import type { SigningAlgorithm } from "./AlgorithmGuard";

/**
 * Story 1.1: HMAC secret length and entropy validation.
 */
export class SecretValidator {
  static validateHmacSecret(
    secret: string,
    _algorithm?: SigningAlgorithm,
  ): void {
    if (secret.length < defaults.minHmacSecretLength) {
      throw new SecurityConfigurationError(
        `HMAC secret must be at least ${defaults.minHmacSecretLength} characters`,
      );
    }
    EntropyValidator.assertHighEntropy(secret);
  }

  static assertHighEntropy(secret: string): void {
    EntropyValidator.assertHighEntropy(secret);
  }
}
