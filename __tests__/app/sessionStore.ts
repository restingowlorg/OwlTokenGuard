import type { SessionRevocationContext } from "../../src/validation/types";
import type { SessionTerminateContext } from "../../src/core/types";

/**
 * In-memory session store — replace with your database or cache in production.
 */
export class SessionStore {
  private readonly activeRefreshJtis = new Set<string>();
  private readonly consumedRefreshJtis = new Set<string>();
  private readonly revokedJtis = new Set<string>();
  private readonly invalidBeforeBySub = new Map<string, number>();
  private readonly minimumReauthAtBySub = new Map<string, number>();

  /** Called from onRefreshTokenIssued — persist a newly issued refresh token. */
  saveRefreshToken(jti: string): void {
    this.activeRefreshJtis.add(jti);
  }

  /** Called from consumeRefreshToken during rotation (RTR). */
  async consumeRefreshToken(jti: string): Promise<boolean> {
    if (this.revokedJtis.has(jti)) return false;
    if (this.consumedRefreshJtis.has(jti)) return false;
    if (!this.activeRefreshJtis.has(jti)) return false;

    this.consumedRefreshJtis.add(jti);
    return true;
  }

  /** Called from onSessionTerminate — logout, rotation, or explicit revoke. */
  async terminateSession(context: SessionTerminateContext): Promise<void> {
    this.revokedJtis.add(context.jti);
    this.activeRefreshJtis.delete(context.jti);

    if (context.sub !== undefined && context.invalidateBefore !== undefined) {
      this.invalidBeforeBySub.set(context.sub, context.invalidateBefore);
    }
  }

  /** Called from getMinimumReauthAt — reject tokens stale after email/MFA change. */
  async getMinimumReauthAt(sub: string): Promise<number | undefined> {
    return this.minimumReauthAtBySub.get(sub);
  }

  /** Bump after email or MFA change to invalidate older sessions. */
  bumpMinimumReauthAt(sub: string, minimum: number): void {
    this.minimumReauthAtBySub.set(sub, minimum);
  }

  /** Called from getTokensInvalidBefore — enforce issued-before cutoff policies. */
  async getTokensInvalidBefore(sub: string): Promise<number | undefined> {
    return this.invalidBeforeBySub.get(sub);
  }

  /** Called from isSessionRevoked — block reuse of terminated sessions. */
  async isSessionRevoked(context: SessionRevocationContext): Promise<boolean> {
    return this.revokedJtis.has(context.jti);
  }

  clear(): void {
    this.activeRefreshJtis.clear();
    this.consumedRefreshJtis.clear();
    this.revokedJtis.clear();
    this.invalidBeforeBySub.clear();
    this.minimumReauthAtBySub.clear();
  }
}
