import { createPublicKey } from "crypto";
import type { TokenConfig } from "./types";
import type { SigningAlgorithm } from "../security/AlgorithmGuard";
import { AlgorithmGuard, ES256_NAMED_CURVE } from "../security/AlgorithmGuard";
import { SecretValidator } from "../security/SecretValidator";
import { SecurityConfigurationError } from "../errors/SecurityConfigurationError";
import { defaults } from "./defaults";

function isHmacAlgorithm(
  algorithm: SigningAlgorithm,
): algorithm is "HS256" | "HS512" {
  return algorithm === "HS256" || algorithm === "HS512";
}

/**
 * Resolve defaulted configuration once so issuer, verifier, and validation
 * all operate on the same effective security policy.
 */
export function normalizeConfig(config: TokenConfig): TokenConfig {
  const algorithm = config.algorithm ?? defaults.algorithm;

  return {
    ...config,
    algorithm,
    allowedAlgorithms: config.allowedAlgorithms ?? [algorithm],
  };
}

/** Story 1.1: fail-fast config validation at startup. */
export function validateConfig(config: TokenConfig): void {
  validatePositiveIntegerSeconds(config.expiresInSeconds, "expiresInSeconds");

  const algorithm = config.algorithm ?? defaults.algorithm;
  AlgorithmGuard.assertAllowed(algorithm);

  validateRequiredKeyMaterial(config, algorithm);

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

function validateRequiredKeyMaterial(
  config: TokenConfig,
  algorithm: SigningAlgorithm,
): void {
  if (isHmacAlgorithm(algorithm)) {
    if (config.hmacSecret === undefined && config.signingKey === undefined) {
      throw new SecurityConfigurationError(
        "HMAC secret is required for HS256/HS512",
      );
    }

    if (config.hmacSecret !== undefined) {
      validateHmacSecret(config.hmacSecret, algorithm);
    }

    if (config.signingKey !== undefined) {
      validateAlgorithm(algorithm, config.signingKey);
    }
    return;
  }

  if (config.hmacSecret !== undefined) {
    throw new SecurityConfigurationError(
      `HMAC secret cannot be used with asymmetric algorithm "${algorithm}"`,
    );
  }

  if (config.signingKey === undefined) {
    throw new SecurityConfigurationError(
      `Asymmetric signing key is required for ${algorithm}`,
    );
  }

  validateAlgorithm(algorithm, config.signingKey);

  if (config.signingKey.type !== "asymmetric") {
    throw new SecurityConfigurationError(
      `Asymmetric signing key is required for ${algorithm}`,
    );
  }

  validatePublicKey(algorithm, config.signingKey.publicKey);
}

function validatePublicKey(
  algorithm: SigningAlgorithm,
  publicKeyPem: unknown,
): void {
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    throw new SecurityConfigurationError(
      `Public key is required for ${algorithm} verification`,
    );
  }

  try {
    const publicKey = createPublicKey(publicKeyPem);

    if (algorithm === "RS256" && publicKey.asymmetricKeyType !== "rsa") {
      throw new SecurityConfigurationError(
        "RS256 verification requires an RSA public key",
      );
    }

    if (algorithm === "ES256") {
      if (publicKey.asymmetricKeyType !== "ec") {
        throw new SecurityConfigurationError(
          "ES256 verification requires an EC public key",
        );
      }

      const namedCurve = publicKey.asymmetricKeyDetails?.namedCurve;
      if (namedCurve !== ES256_NAMED_CURVE) {
        throw new SecurityConfigurationError(
          `ES256 verification requires the ${ES256_NAMED_CURVE} curve (P-256)`,
        );
      }
    }
  } catch (error) {
    if (error instanceof SecurityConfigurationError) {
      throw error;
    }
    throw new SecurityConfigurationError("Invalid public key PEM");
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
