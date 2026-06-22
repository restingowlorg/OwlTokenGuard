import type { Request, Response, NextFunction } from "express";
import type { TokenManager } from "../core/TokenManager";
import type { VerifyOptions, VerifyResult } from "../validation/types";
import { TokenVerificationError } from "../errors/TokenVerificationError";
import { UntrustedKeySourceError } from "../errors/UntrustedKeySourceError";

export interface ExpressVerifyTokenOptions extends Omit<
  VerifyOptions,
  "onVerified"
> {
  /** Extract raw JWT from request (default: Authorization Bearer). */
  extractToken?: (req: Request) => string | undefined;
  /**
   * Hook after verification succeeds. Receives Express `next` for chain control.
   * If omitted, middleware calls `next()` automatically.
   */
  onVerified?: (
    result: VerifyResult,
    next: NextFunction,
    req: Request,
    res: Response,
  ) => Promise<void> | void;
}

function defaultExtractBearerToken(req: Request): string | undefined {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return undefined;
  const token = header.slice("Bearer ".length).trim();
  return token.length > 0 ? token : undefined;
}

/**
 * Express middleware — runs default verification on every protected request.
 * Attach custom logic via `options.onVerified` or route handlers using `req.auth`.
 */
export function expressVerifyToken(
  tokenManager: TokenManager,
  options: ExpressVerifyTokenOptions = {},
) {
  const {
    onVerified,
    extractToken: extractTokenOption,
    ...verifyOptions
  } = options;
  const extractToken = extractTokenOption ?? defaultExtractBearerToken;

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = extractToken(req);
      if (!token) {
        return res.status(401).json({
          error: "Unauthorized",
          message: "Missing or invalid Authorization header",
        });
      }

      const auth = await tokenManager.verify(token, verifyOptions);
      (req as Request & { auth?: typeof auth }).auth = auth;

      if (onVerified) {
        let advanced = false;
        const advance: NextFunction = (...args) => {
          if (advanced || res.headersSent) return;
          advanced = true;
          next(...args);
        };

        await onVerified(auth, advance, req, res);
        if (!advanced && !res.headersSent) {
          advance();
        }
        return;
      }

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
