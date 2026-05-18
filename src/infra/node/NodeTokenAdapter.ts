import crypto from "crypto";
import { DEFAULTS } from "../../configs/defaults";

/**
 * Node `crypto`-backed primitives. Single place that touches cryptographic APIs.
 */
export class NodeTokenAdapter {
  constructor(private readonly signingSecret: Buffer) {}

  secureRandom(length: number): Buffer {
    return crypto.randomBytes(length);
  }

  fingerprint(plainTokenBytes: Buffer): Buffer {
    return crypto
      .createHmac(DEFAULTS.HMAC_ALGORITHM, this.signingSecret)
      .update(plainTokenBytes)
      .digest();
  }

  fingerprintMatches(plainTokenBytes: Buffer, storedDigest: Buffer): boolean {
    const expected = this.fingerprint(plainTokenBytes);

    if (expected.length !== storedDigest.length) {
      return false;
    }

    return crypto.timingSafeEqual(expected, storedDigest);
  }
}
