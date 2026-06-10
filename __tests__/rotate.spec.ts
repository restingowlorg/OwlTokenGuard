import type { TokenConfig } from "../src/config/types";
import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { decodeUnsafeJwtPayload } from "../src/jwt/JwtSigner";
import { TEST_HMAC_SECRET } from "./helpers/keys";

function createRefreshManager(overrides: Partial<TokenConfig> = {}) {
  return createTokenManager({
    algorithm: "HS256",
    hmacSecret: TEST_HMAC_SECRET,
    expiresInSeconds: 900,
    refreshTokenEnabled: true,
    refreshTokenExpiresInSeconds: 604800,
    ...overrides,
  });
}

describe("TokenManager.rotate", () => {
  it("should return a new access/refresh pair with OAuth-standard fields", async () => {
    const manager = createRefreshManager();

    const login = await manager.generateAccessToken({ sub: "user-1" });

    const rotated = await manager.rotate(login.refreshToken!);

    expect(rotated.token).not.toBe(login.token);
    expect(rotated.refreshToken).not.toBe(login.refreshToken);
    expect(rotated.claims.jti).not.toBe(login.claims.jti);
    expect(rotated.refreshClaims.jti).not.toBe(login.refreshClaims?.jti);
    expect(rotated.previousRefreshJti).toBe(login.refreshClaims?.jti);

    expect(rotated.oauth).toEqual({
      access_token: rotated.token,
      token_type: "Bearer",
      expires_in: 900,
      refresh_token: rotated.refreshToken,
    });

    const access = decodeUnsafeJwtPayload(rotated.token);
    const refresh = decodeUnsafeJwtPayload(rotated.refreshToken);
    expect(access.sub).toBe("user-1");
    expect(access.token_use).toBe("access");
    expect(refresh.token_use).toBe("refresh");
    expect(refresh.sub).toBe("user-1");
  });

  it("should terminate the previous refresh session jti after rotation", async () => {
    const terminated: string[] = [];
    const manager = createRefreshManager({
      onSessionTerminate: async ({ jti }) => {
        terminated.push(jti);
      },
    });

    const login = await manager.generateAccessToken({ sub: "user-2" });
    await manager.rotate(login.refreshToken!);

    expect(terminated).toContain(login.refreshClaims?.jti);
  });

  it("should persist the new refresh token via onRefreshTokenIssued", async () => {
    const saved: string[] = [];
    const manager = createRefreshManager({
      onRefreshTokenIssued: async ({ refreshClaims }) => {
        saved.push(refreshClaims.jti);
      },
    });

    const login = await manager.generateAccessToken({ sub: "user-3" });
    const rotated = await manager.rotate(login.refreshToken!);

    expect(saved).toContain(login.refreshClaims?.jti);
    expect(saved).toContain(rotated.refreshClaims.jti);
  });

  it("should reject an access token presented to rotate()", async () => {
    const manager = createRefreshManager();
    const login = await manager.generateAccessToken({ sub: "user-4" });

    await expect(manager.rotate(login.token)).rejects.toThrow(
      /cannot be used as a refresh token/i,
    );
  });

  it("should reject when consumeRefreshToken returns false", async () => {
    const usedForRotation = new Set<string>();
    const manager = createRefreshManager({
      consumeRefreshToken: async ({ jti }) => {
        if (usedForRotation.has(jti)) return false;
        usedForRotation.add(jti);
        return true;
      },
    });

    const login = await manager.generateAccessToken({ sub: "user-5" });
    await manager.rotate(login.refreshToken!);

    await expect(manager.rotate(login.refreshToken!)).rejects.toThrow(
      /already been used/i,
    );
  });

  it("should reject rotation when refresh tokens are disabled", async () => {
    const manager = createTokenManager({
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      expiresInSeconds: 900,
    });

    await expect(manager.rotate("any.token.here")).rejects.toThrow(
      /refreshTokenEnabled/i,
    );
  });

  it("should reject a revoked refresh token via isSessionRevoked", async () => {
    const revoked = new Set<string>();
    const manager = createRefreshManager({
      isSessionRevoked: async (jti) => revoked.has(jti),
    });

    const login = await manager.generateAccessToken({ sub: "user-6" });
    revoked.add(login.refreshClaims!.jti);

    await expect(manager.rotate(login.refreshToken!)).rejects.toThrow(/revoked/i);
  });
});


// Express route
// app.post("/auth/refresh", async (req, res) => {
//   const refreshToken = req.cookies.refresh_token ?? req.body.refresh_token;
//   if (!refreshToken) {
//     return res.status(400).json({ error: "invalid_request", error_description: "Missing refresh token" });
//   }
//   try {
//     const result = await tokenManager.rotate(refreshToken);
//     // RFC 6749 OAuth token response
//     return res.json(result.oauth);
//      {
//        "access_token": "...",
//        "token_type": "Bearer",
//        "expires_in": 900,
//        "refresh_token": "..."
//     }
//   } catch {
//     return res.status(401).json({ error: "invalid_grant", error_description: "Invalid or expired refresh token" });
//   }
// });