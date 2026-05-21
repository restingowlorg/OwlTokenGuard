import { randomBytes } from "crypto";
import { SecurityConfigurationError } from "../errors/SecurityConfigurationError";
import type {
  ReferenceTokenOptions,
  ReferenceTokenResult,
} from "./types";

const MIN_ENTROPY_BITS = 128;

/**
 * Story 1.2: high-entropy opaque identifiers via crypto.randomBytes.
 * Non-sequential; suitable for backend-stored sessions (ASVS 7.2.3).
 */
export class ReferenceTokenGenerator {
  generate(options: ReferenceTokenOptions = {}): ReferenceTokenResult {
    const entropyBits = options.entropyBits ?? MIN_ENTROPY_BITS;
    if (!Number.isInteger(entropyBits) || entropyBits < MIN_ENTROPY_BITS) {
      throw new SecurityConfigurationError(
        `Opaque token requires at least ${MIN_ENTROPY_BITS} bits of entropy`,
      );
    }

    const byteLength = Math.ceil(entropyBits / 8);
    const bytes = randomBytes(byteLength);
    const encoding = options.encoding ?? "base64url";

    const token =
      encoding === "uuidv4"
        ? ReferenceTokenGenerator.toUuidV4(bytes)
        : bytes.toString("base64url");

    return { token, encoding, entropyBits };
  }

  /** RFC 4122 UUID v4 from 16 cryptographically random bytes. */
  private static toUuidV4(bytes: Buffer): string {
    const b = Buffer.from(bytes);
    if (b.length < 16) {
      throw new SecurityConfigurationError(
        "UUIDv4 encoding requires at least 16 bytes of entropy",
      );
    }
    const slice = b.subarray(0, 16);
    slice[6] = (slice[6] & 0x0f) | 0x40;
    slice[8] = (slice[8] & 0x3f) | 0x80;
    const hex = slice.toString("hex");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  }
}
