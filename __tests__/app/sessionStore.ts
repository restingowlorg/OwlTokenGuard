/**
 * In-memory session store — replace with your database or cache in production.
 */
export class SessionStore {
  private readonly activeRefreshJtis = new Set<string>();
  private readonly consumedRefreshJtis = new Set<string>();
  private readonly revokedJtis = new Set<string>();

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
  async terminateSession(jti: string): Promise<void> {
    this.revokedJtis.add(jti);
    this.activeRefreshJtis.delete(jti);
  }

  /** Called from isSessionRevoked — block reuse of terminated sessions. */
  async isSessionRevoked(jti: string): Promise<boolean> {
    return this.revokedJtis.has(jti);
  }

  clear(): void {
    this.activeRefreshJtis.clear();
    this.consumedRefreshJtis.clear();
    this.revokedJtis.clear();
  }
}
