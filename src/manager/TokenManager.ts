import { OpaqueToken } from "../domain/OpaqueToken";
import { TokenFingerprint } from "../domain/TokenFingerprint";
import { OpaqueTokenIssuanceService } from "../service/OpaqueTokenIssuanceService";
import { TokenFingerprintService } from "../service/TokenFingerprintService";

/** Application-facing API for foundational token workflows. */
export class TokenManager {
  constructor(
    private readonly issuance: OpaqueTokenIssuanceService,
    private readonly fingerprints: TokenFingerprintService
  ) {}

  issueOpaque(): OpaqueToken {
    return this.issuance.issue();
  }

  fingerprintForStorage(token: OpaqueToken): TokenFingerprint {
    return this.fingerprints.fromOpaque(token);
  }

  fingerprintFromBytes(presentedTokenBytes: Buffer): TokenFingerprint {
    return this.fingerprints.fromBytes(presentedTokenBytes);
  }

  verifyAgainstFingerprint(
    presentedTokenBytes: Buffer,
    stored: TokenFingerprint
  ): boolean {
    return this.fingerprints.matches(presentedTokenBytes, stored);
  }
}
