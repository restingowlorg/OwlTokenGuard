import { OpaqueToken } from "../domain/OpaqueToken";
import { TokenFingerprint } from "../domain/TokenFingerprint";
import { InsecureTokenUsageError } from "../errors/InsecureTokenUsageError";
import { NodeTokenAdapter } from "../infra/node/NodeTokenAdapter";

export class TokenFingerprintService {
  constructor(private readonly adapter: NodeTokenAdapter) {}

  fromOpaque(token: OpaqueToken): TokenFingerprint {
    return this.fromBytes(token.value);
  }

  fromBytes(plainTokenBytes: Buffer): TokenFingerprint {
    if (!plainTokenBytes || plainTokenBytes.length === 0) {
      throw new InsecureTokenUsageError("Cannot fingerprint an empty token");
    }
    return new TokenFingerprint(this.adapter.fingerprint(plainTokenBytes));
  }

  matches(
    presentedTokenBytes: Buffer,
    stored: TokenFingerprint
  ): boolean {
    if (!presentedTokenBytes || presentedTokenBytes.length === 0) {
      return false;
    }
    return this.adapter.fingerprintMatches(
      presentedTokenBytes,
      stored.digest
    );
  }
}
