import {
  createHmac,
  sign,
  type KeyObject,
} from "crypto";
import {
  resolveSigningMaterial,
  type ResolvedSigningMaterial,
} from "../../src/jwt/JwtSigner";
import type { TokenConfig } from "../../src/config/types";
import { defaults } from "../../src/config/defaults";
import type { SigningAlgorithm } from "../../src/security/AlgorithmGuard";

function base64url(value: string | Buffer): string {
  const buf = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  return buf.toString("base64url");
}

function signInput(
  signingInput: string,
  material: ResolvedSigningMaterial,
): string {
  let signature: Buffer;
  if (material.kind === "hmac") {
    const hash = material.algorithm === "HS512" ? "sha512" : "sha256";
    signature = createHmac(hash, material.secret)
      .update(signingInput)
      .digest();
  } else if (material.algorithm === "RS256") {
    signature = sign("RSA-SHA256", Buffer.from(signingInput), material.privateKey);
  } else {
    signature = sign("sha256", Buffer.from(signingInput), {
      key: material.privateKey,
      dsaEncoding: "ieee-p1363",
    });
  }
  return base64url(signature);
}

export function buildUnsignedJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  const headerSegment = base64url(JSON.stringify(header));
  const payloadSegment = base64url(JSON.stringify(payload));
  return `${headerSegment}.${payloadSegment}.signature`;
}

export function buildSignedTestJwt(
  config: TokenConfig,
  payload: Record<string, unknown>,
  headerOverrides: Record<string, unknown> = {},
): string {
  const algorithm = (config.algorithm ?? defaults.algorithm) as SigningAlgorithm;
  const now = Math.floor(Date.now() / 1000);
  const jwtPayload = {
    iat: now,
    nbf: now,
    jti: "test-jti",
    exp: now + config.expiresInSeconds,
    token_use: "access",
    ...payload,
  };
  const material = resolveSigningMaterial(algorithm, {
    hmacSecret: config.hmacSecret,
    signingKey: config.signingKey,
  });
  const header = { alg: algorithm, typ: "JWT", ...headerOverrides };
  const headerSegment = base64url(JSON.stringify(header));
  const payloadSegment = base64url(JSON.stringify(jwtPayload));
  const signingInput = `${headerSegment}.${payloadSegment}`;
  return `${signingInput}.${signInput(signingInput, material)}`;
}
