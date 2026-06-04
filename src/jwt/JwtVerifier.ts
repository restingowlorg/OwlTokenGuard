import {
  createHmac,
  createPublicKey,
  timingSafeEqual,
  verify,
  type KeyObject,
} from "crypto";
import { TokenVerificationError } from "../errors/TokenVerificationError";
import type { SigningAlgorithm } from "../security/AlgorithmGuard";
import { AlgorithmGuard } from "../security/AlgorithmGuard";
import { TrustedKeySourceGuard } from "../security/TrustedKeySourceGuard";
import type { TokenConfig } from "../config/types";

export interface ParsedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
}

export type ResolvedVerificationMaterial =
  | { kind: "hmac"; secret: string; algorithm: "HS256" | "HS512" }
  | {
      kind: "asymmetric";
      publicKey: KeyObject;
      algorithm: "RS256" | "ES256";
    };

function decodeJsonSegment(segment: string, label: string): Record<string, unknown> {
  try {
    const json = Buffer.from(segment, "base64url").toString("utf8");
    const value = JSON.parse(json) as unknown;
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new TokenVerificationError(`JWT ${label} must be a JSON object`);
    }
    return value as Record<string, unknown>;
  } catch (error) {
    if (error instanceof TokenVerificationError) throw error;
    throw new TokenVerificationError(`Failed to parse JWT ${label}`);
  }
}

/**
 * Story 2.1: signature-first verification — header parsed, signature checked, then payload trusted.
 */
export function verifyJwtSignatureFirst(
  token: string,
  config: TokenConfig,
): ParsedJwt {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new TokenVerificationError("Invalid JWT format");
  }

  const [headerSegment, payloadSegment, signatureSegment] = parts;
  const header = decodeJsonSegment(headerSegment, "header");
  const signingInput = `${headerSegment}.${payloadSegment}`;

  const alg = header.alg;
  if (typeof alg !== "string") {
    throw new TokenVerificationError("JWT header is missing alg");
  }

  if (alg.toLowerCase() === "none") {
    throw new TokenVerificationError('Algorithm "none" is not permitted');
  }

  AlgorithmGuard.assertAllowed(alg);
  assertAlgorithmPermitted(alg as SigningAlgorithm, config);

  TrustedKeySourceGuard.assertTrustedHeaders(
    header,
    config.trustedKeySourceDomains,
  );

  const material = resolveVerificationMaterial(alg as SigningAlgorithm, config);
  assertKeyConfusionProtection(alg as SigningAlgorithm, material);

  const signature = Buffer.from(signatureSegment, "base64url");
  if (!verifySignature(signingInput, signature, material)) {
    throw new TokenVerificationError("JWT signature verification failed");
  }

  const payload = decodeJsonSegment(payloadSegment, "payload");
  return { header, payload, signingInput };
}

function assertAlgorithmPermitted(
  algorithm: SigningAlgorithm,
  config: TokenConfig,
): void {
  const allowed =
    config.allowedAlgorithms ??
    (config.algorithm ? [config.algorithm] : undefined);
  if (!allowed || allowed.length === 0) {
    throw new TokenVerificationError("Verification allowlist is required");
  }
  if (!allowed.includes(algorithm)) {
    throw new TokenVerificationError(
      `Algorithm "${algorithm}" is not in the verification allowlist`,
    );
  }
}

function assertKeyConfusionProtection(
  algorithm: SigningAlgorithm,
  material: ResolvedVerificationMaterial,
): void {
  const isHmac = algorithm === "HS256" || algorithm === "HS512";
  if (isHmac && material.kind !== "hmac") {
    throw new TokenVerificationError(
      "Key confusion: HMAC algorithm requires symmetric verification key",
    );
  }
  if (!isHmac && material.kind !== "asymmetric") {
    throw new TokenVerificationError(
      "Key confusion: asymmetric algorithm requires public key verification",
    );
  }
}

function verifySignature(
  signingInput: string,
  signature: Buffer,
  material: ResolvedVerificationMaterial,
): boolean {
  if (material.kind === "hmac") {
    const hash = material.algorithm === "HS512" ? "sha512" : "sha256";
    const expected = createHmac(hash, material.secret)
      .update(signingInput)
      .digest();
    return (
      expected.length === signature.length &&
      timingSafeEqual(expected, signature)
    );
  }

  if (material.algorithm === "RS256") {
    return verify(
      "RSA-SHA256",
      Buffer.from(signingInput),
      material.publicKey,
      signature,
    );
  }

  return verify(
    "sha256",
    Buffer.from(signingInput),
    { key: material.publicKey, dsaEncoding: "ieee-p1363" },
    signature,
  );
}

export function resolveVerificationMaterial(
  algorithm: SigningAlgorithm,
  config: TokenConfig,
): ResolvedVerificationMaterial {
  if (algorithm === "HS256" || algorithm === "HS512") {
    const secret =
      config.hmacSecret ??
      (config.signingKey?.type === "symmetric"
        ? config.signingKey.secret
        : undefined);
    if (!secret) {
      throw new TokenVerificationError(
        "HMAC secret is required to verify HS256/HS512 tokens",
      );
    }
    return { kind: "hmac", secret, algorithm };
  }

  const publicKeyPem =
    config.signingKey?.type === "asymmetric"
      ? config.signingKey.publicKey
      : undefined;
  if (!publicKeyPem) {
    throw new TokenVerificationError(
      `Public key is required to verify ${algorithm} tokens`,
    );
  }

  const publicKey = createPublicKey(publicKeyPem);
  if (algorithm === "RS256" && publicKey.asymmetricKeyType !== "rsa") {
    throw new TokenVerificationError("RS256 verification requires an RSA public key");
  }
  if (algorithm === "ES256" && publicKey.asymmetricKeyType !== "ec") {
    throw new TokenVerificationError("ES256 verification requires an EC public key");
  }

  return {
    kind: "asymmetric",
    publicKey,
    algorithm,
  };
}
