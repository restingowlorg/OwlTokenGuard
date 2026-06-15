import type { TokenConfig } from "../config/types";
import type { VerifyOptions } from "../validation/types";
import type { TokenVerifier } from "./TokenVerifier";
import type { RevokeTokenOptions, SessionHandle } from "./types";
import { TokenGenerationError } from "../errors/TokenGenerationError";
import { DefaultLogger, type ILogger } from "../utils/Logger";

function resolveSessionJti(session: SessionHandle): string {
  const jti = session.jti;
  if (typeof jti !== "string" || jti.length === 0) {
    throw new TokenGenerationError(
      "Session handle must include a non-empty jti from issuance or verified claims",
    );
  }
  return jti;
}

/**
 * Session revocation — terminate by server-owned jti or by verifying a JWT from logout.
 */
export class TokenTerminator {
  private readonly logger: ILogger;

  constructor(
    private readonly config: TokenConfig,
    private readonly verifier: TokenVerifier,
  ) {
    this.logger = config.customLogger ?? new DefaultLogger(config.debug);
  }

  /**
   * Revoke a session by jti or verified claims — not by raw JWT string.
   * Invokes `onSessionTerminate` so the developer can remove the session from storage.
   */
  async terminate(session: SessionHandle): Promise<void> {
    const jti = resolveSessionJti(session);

    if (this.config.onSessionTerminate) {
      await this.config.onSessionTerminate({ jti });
      this.logger.debug(`[TokenTerminator] terminated session jti=${jti}`);
    }
  }

  /**
   * Verify a JWT and revoke its session — use from `POST /auth/logout`.
   * Pass a refresh token with `{ purpose: "refresh" }` when ending a refresh session.
   */
  async revokeToken(
    token: string,
    options: RevokeTokenOptions = {},
  ): Promise<void> {
    const verifyOptions: VerifyOptions = {};
    if (options.purpose !== undefined) {
      verifyOptions.purpose = options.purpose;
    }

    const verified = await this.verifier.verify(token, verifyOptions);
    await this.terminate(verified.claims);
  }
}
