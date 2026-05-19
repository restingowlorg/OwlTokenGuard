import type { TokenConfig } from "./types";
import type { SigningAlgorithm } from "../security/AlgorithmGuard";

export function validateConfig(_config: TokenConfig): void {
}

export function validateHmacSecret(_secret: string, _algorithm: SigningAlgorithm): void {
}

export function validateAlgorithm(
  _algorithm: SigningAlgorithm,
  _key: TokenConfig["signingKey"],
): void {
}
