import { createPrivateKey, type KeyObject } from "crypto";
import { SecurityConfigurationError } from "../errors/SecurityConfigurationError";
import type { SigningKeyMaterial } from "../config/types";
import { SecretValidator } from "./SecretValidator";

export type SigningAlgorithm =
  | "RS256"
  | "ES256"
  | "HS256"
  | "HS512";

const BLOCKED_ALGORITHMS = ["none", "NONE"] as const;

const ALLOWED_ALGORITHMS: readonly SigningAlgorithm[] = [
  "RS256",
  "ES256",
  "HS256",
  "HS512",
];

const HMAC_ALGORITHMS: readonly SigningAlgorithm[] = ["HS256", "HS512"];

const ASYMMETRIC_ALGORITHMS: readonly SigningAlgorithm[] = ["RS256", "ES256"];

function isHmacAlgorithm(
  algorithm: SigningAlgorithm,
): algorithm is "HS256" | "HS512" {
  return (HMAC_ALGORITHMS as readonly string[]).includes(algorithm);
}

/**
 * Story 1.1: blocks `none` and unauthorized hashing types.
 */
export class AlgorithmGuard {
  static assertAllowed(algorithm: string): asserts algorithm is SigningAlgorithm {
    if ((BLOCKED_ALGORITHMS as readonly string[]).includes(algorithm)) {
      throw new SecurityConfigurationError(
        `Algorithm "${algorithm}" is not permitted`,
      );
    }

    if (!(ALLOWED_ALGORITHMS as readonly string[]).includes(algorithm)) {
      throw new SecurityConfigurationError(
        `Algorithm "${algorithm}" is not supported. Allowed: ${ALLOWED_ALGORITHMS.join(", ")}`,
      );
    }
  }

  /** Story 1.1: ensure signing key matches algorithm (key confusion prevention). */
  static validateAlgorithm(
    algorithm: SigningAlgorithm,
    keyMaterial: SigningKeyMaterial | string | undefined,
  ): void {
    if (keyMaterial === undefined || keyMaterial === "") {
      throw new SecurityConfigurationError(
        "Signing key material is required for the selected algorithm",
      );
    }

    if (typeof keyMaterial === "string") {
      if (!isHmacAlgorithm(algorithm)) {
        throw new SecurityConfigurationError(
          `Symmetric secret cannot be used with asymmetric algorithm "${algorithm}"`,
        );
      }
      SecretValidator.validateHmacSecret(keyMaterial, algorithm);
      return;
    }

    if (keyMaterial.type === "symmetric") {
      if (!isHmacAlgorithm(algorithm)) {
        throw new SecurityConfigurationError(
          `Symmetric signing key cannot be used with "${algorithm}"`,
        );
      }
      SecretValidator.validateHmacSecret(keyMaterial.secret, algorithm);
      return;
    }

    if (!ASYMMETRIC_ALGORITHMS.includes(algorithm)) {
      throw new SecurityConfigurationError(
        `Asymmetric key cannot be used with HMAC algorithm "${algorithm}"`,
      );
    }

    AlgorithmGuard.assertPrivateKeyMatchesAlgorithm(
      algorithm,
      keyMaterial.privateKey,
    );
  }

  private static assertPrivateKeyMatchesAlgorithm(
    algorithm: SigningAlgorithm,
    privateKeyPem: string,
  ): void {
    let key: KeyObject;
    try {
      key = createPrivateKey(privateKeyPem);
    } catch {
      throw new SecurityConfigurationError("Invalid private key PEM");
    }

    if (algorithm === "RS256" && key.asymmetricKeyType !== "rsa") {
      throw new SecurityConfigurationError(
        "RS256 requires an RSA private key",
      );
    }

    if (algorithm === "ES256" && key.asymmetricKeyType !== "ec") {
      throw new SecurityConfigurationError(
        "ES256 requires an EC private key",
      );
    }
  }
}
