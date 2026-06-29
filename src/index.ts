export { createTokenManager } from "./factories/TokenManagerFactory";
export type { TokenManager } from "./core/TokenManager";
export { ReferenceTokenGenerator } from "./generators/ReferenceTokenGenerator";
export { Aes256GcmCipher } from "./ciphering/Aes256GcmCipher";
export { validateToken } from "./validation/validateToken";
export { createTokenDigest } from "./utils/TokenDigest";
export {
  expressVerifyToken,
  validateTokenMiddleware,
} from "./middlewares/express";
export {
  fastifyVerifyToken,
  validateTokenPreHandler,
} from "./middlewares/fastify";

// Types
export * from "./core/types";
export * from "./config/types";
export * from "./validation/types";
export * from "./generators/types";
export * from "./ciphering/types";
export * from "./security/AlgorithmGuard";

// Errors
export { BaseError } from "./errors/BaseError";
export { SecurityConfigurationError } from "./errors/SecurityConfigurationError";
export { TokenGenerationError } from "./errors/TokenGenerationError";
export { TokenVerificationError } from "./errors/TokenVerificationError";
export { UntrustedKeySourceError } from "./errors/UntrustedKeySourceError";
