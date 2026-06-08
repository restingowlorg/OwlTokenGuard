import type { FastifyReply, FastifyRequest, preHandlerHookHandler } from "fastify";
import type { TokenManager } from "../core/TokenManager";
import type { VerifyOptions, VerifyResult } from "../validation/types";
import { TokenVerificationError } from "../errors/TokenVerificationError";
import { UntrustedKeySourceError } from "../errors/UntrustedKeySourceError";

export interface FastifyVerifyTokenOptions extends Omit<VerifyOptions, "onVerified"> {
  /** Extract raw JWT from request (default: Authorization Bearer). */
  extractToken?: (request: FastifyRequest) => string | undefined;
  /**
   * Hook after verification succeeds. Call `continue` to proceed to the route handler.
   * If omitted, the hook continues automatically when no response is sent.
   */
  onVerified?: (
    result: VerifyResult,
    continueHook: () => void,
    request: FastifyRequest,
    reply: FastifyReply,
  ) => Promise<void> | void;
}

function defaultExtractBearerToken(request: FastifyRequest): string | undefined {
  const header = request.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    return undefined;
  }
  const token = header.slice("Bearer ".length).trim();
  return token.length > 0 ? token : undefined;
}

/**
 * Fastify preHandler — runs default verification on every protected request.
 * Attach custom logic via `options.onVerified` or route handlers using `request.auth`.
 */
export function fastifyVerifyToken(
  tokenManager: TokenManager,
  options: FastifyVerifyTokenOptions = {},
): preHandlerHookHandler {
  const { onVerified, extractToken: extractTokenOption, ...verifyOptions } =
    options;
  const extractToken = extractTokenOption ?? defaultExtractBearerToken;

  return async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const token = extractToken(request);
      if (!token) {
        return reply.status(401).send({
          error: "Unauthorized",
          message: "Missing or invalid Authorization header",
        });
      }

      const auth = await tokenManager.verify(token, verifyOptions);
      request.auth = auth;

      if (onVerified) {
        await onVerified(auth, () => { return void 0; }, request, reply);
        if (reply.sent) {
          return;
        }
      }

    } catch (error) {
      if (
        error instanceof TokenVerificationError ||
        error instanceof UntrustedKeySourceError
      ) {
        return reply.status(401).send({
          error: "Unauthorized",
          message: error.message,
        });
      }
      throw error;
    }
  };
}

/** Alias for fastifyVerifyToken — use as a route preHandler on private endpoints. */
export const validateTokenPreHandler = fastifyVerifyToken;

declare module "fastify" {
  interface FastifyRequest {
    auth?: import("../validation/types").VerifyResult;
  }
}
