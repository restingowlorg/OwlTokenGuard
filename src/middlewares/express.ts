import type { Request, Response, NextFunction } from "express";
import type { TokenManager } from "../core/TokenManager";
import type { VerifyOptions } from "../validation/types";
import { TokenVerificationError } from "../errors/TokenVerificationError";
import { UntrustedKeySourceError } from "../errors/UntrustedKeySourceError";

export interface ExpressVerifyTokenOptions extends VerifyOptions {
  /** Extract raw JWT from request (default: Authorization Bearer). */
  extractToken?: (req: Request) => string | undefined;
}

function defaultExtractBearerToken(req: Request): string | undefined {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return undefined;
  const token = header.slice("Bearer ".length).trim();
  return token.length > 0 ? token : undefined;
}

/**
 * Express middleware — runs default verification on every protected request.
 * Attach custom logic via VerifyOptions.onVerified or route handlers using req.auth.
 */
export function expressVerifyToken(
  tokenManager: TokenManager,
  options: ExpressVerifyTokenOptions = {},
) {
  const extractToken = options.extractToken ?? defaultExtractBearerToken;

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = extractToken(req);
      if (!token) {
        return res.status(401).json({
          error: "Unauthorized",
          message: "Missing or invalid Authorization header",
        });
      }

      const auth = await tokenManager.verify(token, options);
      (req as Request & { auth?: typeof auth }).auth = auth;
      next();
    } catch (error) {
      if (
        error instanceof TokenVerificationError ||
        error instanceof UntrustedKeySourceError
      ) {
        return res.status(401).json({
          error: "Unauthorized",
          message: error.message,
        });
      }
      next(error);
    }
  };
}

/** Alias for expressVerifyToken — use as route middleware on private endpoints. */
export const validateTokenMiddleware = expressVerifyToken;

declare module "express-serve-static-core" {
  interface Request {
    auth?: import("../validation/types").VerifyResult;
  }
}
