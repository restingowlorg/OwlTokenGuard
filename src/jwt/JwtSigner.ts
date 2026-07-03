import { createHmac, createPrivateKey, sign, type KeyObject } from "crypto";
import { TokenGenerationError } from "../errors/TokenGenerationError";
import type { SigningAlgorithm } from "../security/AlgorithmGuard";

export type ResolvedSigningMaterial =
  | { kind: "hmac"; secret: string; algorithm: "HS256" | "HS512" }
  | {
      kind: "asymmetric";
      privateKey: KeyObject;
      algorithm: "RS256" | "ES256";
    };

function base64url(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return buf.toString("base64url");
}

export function signJwt(
  payload: Record<string, unknown>,
  material: ResolvedSigningMaterial,
): string {
  const header = { alg: material.algorithm, typ: "JWT" as const };
  const headerSegment = base64url(JSON.stringify(header));
  const payloadSegment = base64url(JSON.stringify(payload));
  const signingInput = `${headerSegment}.${payloadSegment}`;

  let signature: Buffer;
  if (material.kind === "hmac") {
    const hash = material.algorithm === "HS512" ? "sha512" : "sha256";
    signature = createHmac(hash, material.secret).update(signingInput).digest();
  } else if (material.algorithm === "RS256") {
    signature = sign(
      "RSA-SHA256",
      Buffer.from(signingInput),
      material.privateKey,
    );
  } else {
    signature = sign("sha256", Buffer.from(signingInput), {
      key: material.privateKey,
      dsaEncoding: "ieee-p1363",
    });
  }

  return `${signingInput}.${base64url(signature)}`;
}

/**
 * Decodes a JWT payload without signature or claim verification.
 * @internal Do not use for authorization — attacker-controlled claims are not trusted.
 */
export function decodeUnsafeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new TokenGenerationError("Invalid JWT format");
  }

  try {
    const json = Buffer.from(parts[1], "base64url").toString("utf8");
    const payload = JSON.parse(json) as unknown;
    if (
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload)
    ) {
      throw new TokenGenerationError("JWT payload must be a JSON object");
    }
    return payload as Record<string, unknown>;
  } catch (error) {
    if (error instanceof TokenGenerationError) throw error;
    throw new TokenGenerationError("Failed to decode JWT payload");
  }
}

export function resolveSigningMaterial(
  algorithm: SigningAlgorithm,
  options: {
    hmacSecret?: string;
    signingKey?: import("../config/types").SigningKeyMaterial;
  },
): ResolvedSigningMaterial {
  const { hmacSecret, signingKey } = options;

  if (algorithm === "HS256" || algorithm === "HS512") {
    const secret =
      hmacSecret ??
      (signingKey?.type === "symmetric" ? signingKey.secret : undefined);
    if (!secret) {
      throw new TokenGenerationError(
        "HMAC secret is required for HS256/HS512 signing",
      );
    }
    return { kind: "hmac", secret, algorithm };
  }

  const privateKeyPem =
    signingKey?.type === "asymmetric" ? signingKey.privateKey : undefined;
  if (!privateKeyPem) {
    throw new TokenGenerationError(
      `Asymmetric private key is required for ${algorithm} signing`,
    );
  }

  const privateKey = createPrivateKey(privateKeyPem);
  return {
    kind: "asymmetric",
    privateKey,
    algorithm,
  };
}
