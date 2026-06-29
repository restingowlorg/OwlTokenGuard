import { createHash, createHmac } from "crypto";
import { SecurityConfigurationError } from "../errors/SecurityConfigurationError";

export interface TokenDigestOptions {
  /**
   * Application-held secret used to HMAC the token before storage.
   * Prefer this for database lookups because plain SHA-256 digests of leaked
   * tokens can be brute-forced if the token source is weak.
   */
  pepper?: string | Buffer;
}

export function createTokenDigest(
  token: string,
  options: TokenDigestOptions = {},
): string {
  if (typeof token !== "string" || token.length === 0) {
    throw new SecurityConfigurationError(
      "token must be a non-empty string to create a digest",
    );
  }

  if (options.pepper !== undefined) {
    validatePepper(options.pepper);
    return `hmac-sha256:${createHmac("sha256", options.pepper)
      .update(token, "utf8")
      .digest("base64url")}`;
  }

  return `sha256:${createHash("sha256")
    .update(token, "utf8")
    .digest("base64url")}`;
}

function validatePepper(pepper: string | Buffer): void {
  if (
    (typeof pepper === "string" && pepper.length === 0) ||
    (Buffer.isBuffer(pepper) && pepper.length === 0)
  ) {
    throw new SecurityConfigurationError(
      "pepper must be non-empty when configured",
    );
  }
}
