import express, { type Express, type Request, type Response } from "express";
import type { TokenManager } from "../../src/core/TokenManager";
import { expressVerifyToken } from "../../src/middlewares/express";
import { TokenVerificationError } from "../../src/errors/TokenVerificationError";
import { TokenGenerationError } from "../../src/errors/TokenGenerationError";
import { SessionStore } from "./sessionStore";
import { createShowcaseTokenManager } from "./tokenManager";

export interface ShowcaseApp {
  app: Express;
  tokenManager: TokenManager;
  sessionStore: SessionStore;
}

/**
 * Minimal Express app demonstrating TokenManager usage.
 *
 * Endpoints:
 *   GET  /health
 *   POST /auth/login          — issue access + refresh tokens
 *   POST /auth/refresh        — rotate refresh token (RFC 6749 response)
 *   POST /auth/logout         — revoke refresh session
 *   GET  /auth/me             — protected route (Bearer access token)
 *   POST /auth/reference      — issue opaque reference token
 *   POST /auth/generate       — issue JWT + reference token (compatibility API)
 *   POST /auth/verify         — manually verify any token
 *   POST /auth/terminate      — terminate session by jti (server-side revoke)
 */
export function createShowcaseApp(
  dependencies?: {
    tokenManager?: TokenManager;
    sessionStore?: SessionStore;
  },
): ShowcaseApp {
  const sessionStore = dependencies?.sessionStore ?? new SessionStore();
  const tokenManager =
    dependencies?.tokenManager ?? createShowcaseTokenManager(sessionStore);

  const app = express();
  app.use(express.json());

  const requireAccessToken = expressVerifyToken(tokenManager, {
    purpose: "access",
  });

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  // POST /auth/login  { "sub": "user-1", "role": "admin" }
  app.post("/auth/login", async (req: Request, res: Response) => {
    try {
      const sub = req.body?.sub;
      if (typeof sub !== "string" || sub.length === 0) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "sub is required",
        });
      }

      const payload: Record<string, unknown> = { sub };
      if (req.body?.role !== undefined) {
        payload.role = req.body.role;
      }

      const issued = await tokenManager.generateAccessToken(payload, {
        reauthAt:
          typeof req.body?.reauth_at === "number"
            ? req.body.reauth_at
            : Math.floor(Date.now() / 1000),
      });

      return res.status(200).json({
        access_token: issued.token,
        token_type: "Bearer",
        expires_in: tokenManager.config.expiresInSeconds,
        refresh_token: issued.refreshToken,
        claims: issued.claims,
        refresh_claims: issued.refreshClaims,
      });
    } catch (error) {
      return sendTokenError(res, error);
    }
  });

  // POST /auth/refresh  { "refresh_token": "..." }
  app.post("/auth/refresh", async (req: Request, res: Response) => {
    try {
      const refreshToken = req.body?.refresh_token;
      if (typeof refreshToken !== "string" || refreshToken.length === 0) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "refresh_token is required",
        });
      }

      const rotated = await tokenManager.rotate(refreshToken);
      return res.status(200).json(rotated.oauth);
    } catch (error) {
      return sendTokenError(res, error, 401);
    }
  });

  // POST /auth/logout  { "refresh_token": "..." }
  app.post("/auth/logout", async (req: Request, res: Response) => {
    try {
      const refreshToken = req.body?.refresh_token;
      if (typeof refreshToken !== "string" || refreshToken.length === 0) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "refresh_token is required",
        });
      }

      await tokenManager.revokeToken(refreshToken, { purpose: "refresh" });
      return res.status(204).send();
    } catch (error) {
      return sendTokenError(res, error, 401);
    }
  });

  // GET /auth/me  Authorization: Bearer <access_token>
  app.get("/auth/me", requireAccessToken, (req: Request, res: Response) => {
    res.json({
      sub: req.auth?.payload.sub,
      jti: req.auth?.jti,
      claims: req.auth?.claims,
      payload: req.auth?.payload,
    });
  });

  // POST /auth/reference
  app.post("/auth/reference", (_req: Request, res: Response) => {
    const reference = tokenManager.generateReferenceToken();
    res.status(201).json(reference);
  });

  // POST /auth/generate  { "sub": "user-1" }
  app.post("/auth/generate", async (req: Request, res: Response) => {
    try {
      const sub = req.body?.sub;
      if (typeof sub !== "string" || sub.length === 0) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "sub is required",
        });
      }

      const issued = await tokenManager.generate({ sub });
      return res.status(201).json({
        token: issued.token,
        refresh_token: issued.refreshToken,
        reference_token: issued.referenceToken,
        claims: issued.claims,
      });
    } catch (error) {
      return sendTokenError(res, error);
    }
  });

  // POST /auth/verify  { "token": "...", "purpose": "access" | "refresh" }
  app.post("/auth/verify", async (req: Request, res: Response) => {
    try {
      const token = req.body?.token;
      if (typeof token !== "string" || token.length === 0) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "token is required",
        });
      }

      const purpose = req.body?.purpose;
      const verified = await tokenManager.verify(token, {
        purpose:
          purpose === "access" || purpose === "refresh" || purpose === "id"
            ? purpose
            : undefined,
      });

      return res.status(200).json({
        valid: true,
        jti: verified.jti,
        claims: verified.claims,
        payload: verified.payload,
      });
    } catch (error) {
      return sendTokenError(res, error, 401);
    }
  });

  // POST /auth/terminate  { "jti": "..." }
  app.post("/auth/terminate", async (req: Request, res: Response) => {
    try {
      const jti = req.body?.jti;
      if (typeof jti !== "string" || jti.length === 0) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "jti is required",
        });
      }

      await tokenManager.terminate({ jti });
      return res.status(204).send();
    } catch (error) {
      return sendTokenError(res, error);
    }
  });

  return { app, tokenManager, sessionStore };
}

function sendTokenError(
  res: Response,
  error: unknown,
  status = 400,
): Response {
  if (
    error instanceof TokenVerificationError ||
    error instanceof TokenGenerationError
  ) {
    return res.status(status).json({
      error: "invalid_grant",
      error_description: error.message,
    });
  }

  throw error;
}
