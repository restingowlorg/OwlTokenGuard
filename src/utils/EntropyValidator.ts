import { SecurityConfigurationError } from "../errors/SecurityConfigurationError";

const WEAK_SECRETS = new Set([
  "password",
  "secret",
  "test",
  "testing",
  "development",
  "changeme",
  "admin",
  "default",
  "123456",
  "qwerty",
  "letmein",
  "welcome",
  "monkey",
  "dragon",
  "master",
  "jwt_secret",
  "your-256-bit-secret",
]);

/** Minimum Shannon entropy (bits per character) for signing secrets. */
const MIN_ENTROPY_PER_CHAR = 3.0;

/**
 * Story 1.1: detect predictable or low-entropy signing secrets.
 */
export class EntropyValidator {
  static assertHighEntropy(value: string): void {
    const trimmed = value.trim();
    if (trimmed.length === 0) {
      throw new SecurityConfigurationError("Signing secret must not be empty");
    }

    const normalized = trimmed.toLowerCase();
    if (WEAK_SECRETS.has(normalized)) {
      throw new SecurityConfigurationError(
        "Signing secret matches a known weak or predictable value",
      );
    }

    if (/^(.)\1+$/.test(trimmed)) {
      throw new SecurityConfigurationError(
        "Signing secret must not consist of a single repeated character",
      );
    }

    if (/^(0123456789|abcdefghijklmnopqrstuvwxyz)+$/i.test(normalized)) {
      throw new SecurityConfigurationError(
        "Signing secret must not be a sequential or trivial pattern",
      );
    }

    const entropy = EntropyValidator.shannonEntropy(trimmed);
    if (entropy < MIN_ENTROPY_PER_CHAR) {
      throw new SecurityConfigurationError(
        `Signing secret entropy too low (${entropy.toFixed(2)} bits/char; minimum ${MIN_ENTROPY_PER_CHAR})`,
      );
    }
  }

  private static shannonEntropy(value: string): number {
    const frequencies = new Map<string, number>();
    for (const char of value) {
      frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
    }

    let entropy = 0;
    for (const count of frequencies.values()) {
      const probability = count / value.length;
      entropy -= probability * Math.log2(probability);
    }
    return entropy;
  }
}
