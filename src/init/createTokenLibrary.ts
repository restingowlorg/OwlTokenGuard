import { TokenManager } from "../manager/TokenManager";
import { NodeTokenAdapter } from "../infra/node/NodeTokenAdapter";
import { OpaqueTokenIssuanceService } from "../service/OpaqueTokenIssuanceService";
import { TokenFingerprintService } from "../service/TokenFingerprintService";
import type { TokenLibraryOptions } from "../types";
import { InsecureTokenConfigurationError } from "../errors/InsecureTokenConfigurationError";
import { InsecureTokenUsageError } from "../errors/InsecureTokenUsageError";
import { DEFAULTS } from "../configs/defaults";

/** Composition root: validates policy, wires Node adapter → services → manager. */
export function createTokenLibrary(options: TokenLibraryOptions): TokenManager {
  if (options.signingSecret.length < DEFAULTS.MIN_SIGNING_SECRET_BYTES) {
    throw new InsecureTokenConfigurationError(
      `signingSecret must be at least ${DEFAULTS.MIN_SIGNING_SECRET_BYTES} bytes`
    );
  }

  const opaqueLen =
    options.opaqueTokenByteLength ?? DEFAULTS.OPAQUE_TOKEN_BYTES;

  if (
    !Number.isInteger(opaqueLen) ||
    opaqueLen < DEFAULTS.MIN_OPAQUE_TOKEN_BYTES
  ) {
    throw new InsecureTokenUsageError(
      `opaqueTokenByteLength must be an integer >= ${DEFAULTS.MIN_OPAQUE_TOKEN_BYTES}`
    );
  }

  const adapter = new NodeTokenAdapter(options.signingSecret);
  const issuance = new OpaqueTokenIssuanceService(adapter, opaqueLen);
  const fingerprints = new TokenFingerprintService(adapter);

  return new TokenManager(issuance, fingerprints);
}
