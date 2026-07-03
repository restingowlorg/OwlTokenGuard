import { AlgorithmGuard } from "../src/security/AlgorithmGuard";
import { SecurityConfigurationError } from "../src/errors/SecurityConfigurationError";
import {
  generateEcKeyPair,
  generateNonP256EcKeyPair,
  generateRsaKeyPair,
} from "./helpers/keys";

describe("AlgorithmGuard", () => {
  it("should reject the none algorithm", () => {
    expect(() => AlgorithmGuard.assertAllowed("none")).toThrow(
      SecurityConfigurationError,
    );
    expect(() => AlgorithmGuard.assertAllowed("none")).toThrow(
      /not permitted/i,
    );
  });

  it("should allow supported signing algorithms", () => {
    expect(() => AlgorithmGuard.assertAllowed("RS256")).not.toThrow();
    expect(() => AlgorithmGuard.assertAllowed("ES256")).not.toThrow();
    expect(() => AlgorithmGuard.assertAllowed("HS256")).not.toThrow();
    expect(() => AlgorithmGuard.assertAllowed("HS512")).not.toThrow();
  });

  it("should reject unsupported algorithms", () => {
    expect(() => AlgorithmGuard.assertAllowed("HS384")).toThrow(
      SecurityConfigurationError,
    );
  });

  it("should reject missing signing key material", () => {
    expect(() => AlgorithmGuard.validateAlgorithm("HS256", undefined)).toThrow(
      /required/i,
    );
    expect(() => AlgorithmGuard.validateAlgorithm("HS256", "")).toThrow(
      /required/i,
    );
  });

  it("should validate raw string secrets only for HMAC algorithms", () => {
    const secret =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef";

    expect(() =>
      AlgorithmGuard.validateAlgorithm("HS256", secret),
    ).not.toThrow();
    expect(() => AlgorithmGuard.validateAlgorithm("RS256", secret)).toThrow(
      /symmetric secret cannot be used/i,
    );
  });

  it("should accept symmetric key objects for HMAC algorithms", () => {
    expect(() =>
      AlgorithmGuard.validateAlgorithm("HS512", {
        type: "symmetric",
        secret:
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef",
      }),
    ).not.toThrow();
  });

  it("should prevent key confusion between symmetric and asymmetric algorithms", () => {
    const { privateKey, publicKey } = generateRsaKeyPair();
    expect(() =>
      AlgorithmGuard.validateAlgorithm("HS256", {
        type: "asymmetric",
        privateKey,
        publicKey,
      }),
    ).toThrow(SecurityConfigurationError);
  });

  it("should reject symmetric key objects for asymmetric algorithms", () => {
    expect(() =>
      AlgorithmGuard.validateAlgorithm("RS256", {
        type: "symmetric",
        secret:
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef",
      }),
    ).toThrow(/symmetric signing key cannot be used/i);
  });

  it("should reject invalid asymmetric private key PEM", () => {
    expect(() =>
      AlgorithmGuard.validateAlgorithm("RS256", {
        type: "asymmetric",
        privateKey: "not-a-private-key",
        publicKey: "not-a-public-key",
      }),
    ).toThrow(/invalid private key/i);
  });

  it("should reject RSA keys for ES256 and EC keys for RS256", () => {
    const rsa = generateRsaKeyPair();
    const ec = generateEcKeyPair();

    expect(() =>
      AlgorithmGuard.validateAlgorithm("ES256", {
        type: "asymmetric",
        privateKey: rsa.privateKey,
        publicKey: rsa.publicKey,
      }),
    ).toThrow(/EC private key/i);

    expect(() =>
      AlgorithmGuard.validateAlgorithm("RS256", {
        type: "asymmetric",
        privateKey: ec.privateKey,
        publicKey: ec.publicKey,
      }),
    ).toThrow(/RSA private key/i);
  });

  it("should accept P-256 EC keys for ES256 signing", () => {
    const { privateKey, publicKey } = generateEcKeyPair();
    expect(() =>
      AlgorithmGuard.validateAlgorithm("ES256", {
        type: "asymmetric",
        privateKey,
        publicKey,
      }),
    ).not.toThrow();
  });

  it("should reject non-P-256 EC keys for ES256 signing", () => {
    const { privateKey, publicKey } = generateNonP256EcKeyPair();
    expect(() =>
      AlgorithmGuard.validateAlgorithm("ES256", {
        type: "asymmetric",
        privateKey,
        publicKey,
      }),
    ).toThrow(/prime256v1/i);
  });
});
