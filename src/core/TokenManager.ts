import { TokenIssuer } from "./TokenIssuer";
import { TokenVerifier } from "./TokenVerifier";
import type { TokenConfig } from "../config/types";
import { validateConfig } from "../config/validation";
import type {
  TokenPayload,
  GenerateOptions,
  AccessTokenOptions,
  ReferenceIssuanceOptions,
  TokenResult,
  AccessTokenResult,
  SessionReferenceResult,
  SessionHandle,
} from "./types";
import type { VerifyOptions, VerifyResult } from "../validation/types";

/**
 * Token management API. Instantiate only via {@link createTokenManager}.
 */
export class TokenManager {
  private readonly issuer: TokenIssuer;
  private readonly verifier: TokenVerifier;

  private constructor(
    public readonly config: TokenConfig,
    dependencies?: { issuer?: TokenIssuer; verifier?: TokenVerifier },
  ) {
    this.issuer = dependencies?.issuer ?? new TokenIssuer(config);
    this.verifier = dependencies?.verifier ?? new TokenVerifier(config);
  }

  /** Validated construction — prefer `createTokenManager()` from the factory. */
  static create(
    config: TokenConfig,
    dependencies?: { issuer?: TokenIssuer; verifier?: TokenVerifier },
  ): TokenManager {
    validateConfig(config);
    return new TokenManager(config, dependencies);
  }

  async generateAccessToken(
    payload: TokenPayload,
    options?: AccessTokenOptions,
  ): Promise<AccessTokenResult> {
    return this.issuer.issueAccessToken(payload, options);
  }

  generateReferenceToken(
    options?: ReferenceIssuanceOptions,
  ): SessionReferenceResult {
    return this.issuer.issueReferenceToken(options);
  }

  async generate(
    payload: TokenPayload,
    options?: GenerateOptions,
  ): Promise<TokenResult> {
    return this.issuer.issue(payload, options);
  }

  /** Epic 2: fail-shut JWT verification with standard claim checks. */
  async verify(token: string, options?: VerifyOptions): Promise<VerifyResult> {
    return this.verifier.verify(token, options);
  }

  async terminate(session: SessionHandle): Promise<void> {
    return this.issuer.terminate(session);
  }

  async shutdown(): Promise<void> {
    // no-op until external stores are wired
  }
}
