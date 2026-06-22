import type { TokenConfig } from "../config/types";
import type { VerifyOptions } from "../validation/types";
import type { TokenVerifier } from "./TokenVerifier";
import type {
  RevokeTokenOptions,
  SessionHandle,
  TerminateOptions,
} from "./types";
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

function resolveSessionIat(session: SessionHandle): number | undefined {
  return "iat" in session && typeof session.iat === "number"
    ? session.iat
    : undefined;
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
  async terminate(
    session: SessionHandle,
    options: TerminateOptions = {},
  ): Promise<void> {
    const jti = resolveSessionJti(session);

    if (this.config.onSessionTerminate) {
      await this.config.onSessionTerminate({
        jti,
        iat: resolveSessionIat(session),
        sub: options.sub,
        invalidateBefore: options.invalidateBefore,
      });
      this.logger.debug(`[TokenTerminator] terminated session jti=${jti}`);
    }
  }

  /**
   * Verify a JWT and revoke its session — use from `POST /auth/logout`.
   * Pass a refresh token with `{ purpose: "refresh" }` when ending a refresh session.
   */
  async revokeToken(token: string, options: RevokeTokenOptions): Promise<void> {
    const verifyOptions: VerifyOptions = {};
    verifyOptions.purpose = options.purpose;

    const verified = await this.verifier.verify(token, verifyOptions);
    const sub =
      typeof verified.payload.sub === "string"
        ? verified.payload.sub
        : undefined;

    await this.terminate(verified.claims, {
      sub,
      invalidateBefore: options.invalidateBefore,
    });
  }
}
