import type { TokenConfig } from "./types";
import type { SigningAlgorithm } from "../security/AlgorithmGuard";
import { AlgorithmGuard } from "../security/AlgorithmGuard";
import { SecretValidator } from "../security/SecretValidator";
import { SecurityConfigurationError } from "../errors/SecurityConfigurationError";
import { defaults } from "./defaults";

/** Story 1.1: fail-fast config validation at startup. */
export function validateConfig(config: TokenConfig): void {
  validatePositiveIntegerSeconds(config.expiresInSeconds, "expiresInSeconds");

  const algorithm = config.algorithm ?? defaults.algorithm;
  AlgorithmGuard.assertAllowed(algorithm);

  if (config.hmacSecret !== undefined) {
    validateHmacSecret(config.hmacSecret, algorithm);
  }

  if (config.signingKey !== undefined) {
    validateAlgorithm(algorithm, config.signingKey);
  }

  if (config.refreshTokenEnabled) {
    if (config.refreshTokenExpiresInSeconds === undefined) {
      throw new SecurityConfigurationError(
        "refreshTokenExpiresInSeconds is required when refreshTokenEnabled is true",
      );
    }
    validatePositiveIntegerSeconds(
      config.refreshTokenExpiresInSeconds,
      "refreshTokenExpiresInSeconds",
    );
  }
}

function validatePositiveIntegerSeconds(
  value: unknown,
  fieldName: string,
): void {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    !Number.isInteger(value) ||
    value <= 0
  ) {
    throw new SecurityConfigurationError(
      `${fieldName} must be a positive integer number of seconds`,
    );
  }
}

/** Story 1.1: enforce minimum 64-char HMAC secrets (HS256/HS512). */
export function validateHmacSecret(
  secret: string,
  algorithm: SigningAlgorithm,
): void {
  if (!["HS256", "HS512"].includes(algorithm)) {
    throw new SecurityConfigurationError(
      "validateHmacSecret is only applicable to HS256/HS512",
    );
  }
  SecretValidator.validateHmacSecret(secret, algorithm);
}

/** Story 1.1: ensure signing key matches requested algorithm. */
export function validateAlgorithm(
  algorithm: SigningAlgorithm,
  key: TokenConfig["signingKey"],
): void {
  if (key === undefined) {
    return;
  }
  AlgorithmGuard.validateAlgorithm(algorithm, key);
}
