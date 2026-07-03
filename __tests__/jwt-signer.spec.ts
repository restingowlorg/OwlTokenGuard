import {
  decodeUnsafeJwtPayload,
  resolveSigningMaterial,
  signJwt,
} from "../src/jwt/JwtSigner";
import { TokenGenerationError } from "../src/errors/TokenGenerationError";
import { TEST_HMAC_SECRET, generateRsaKeyPair } from "./helpers/keys";

describe("JwtSigner", () => {
  it("should decode an unsigned payload for diagnostics only", () => {
    const material = resolveSigningMaterial("HS256", {
      hmacSecret: TEST_HMAC_SECRET,
    });
    const token = signJwt({ sub: "diagnostic-user" }, material);

    expect(decodeUnsafeJwtPayload(token)).toEqual({
      sub: "diagnostic-user",
    });
  });

  it("should reject unsafe decoding for invalid JWT shapes", () => {
    expect(() => decodeUnsafeJwtPayload("not-a-jwt")).toThrow(
      /invalid JWT format/i,
    );
  });

  it("should reject unsafe decoding when payload JSON is not an object", () => {
    const token = [
      Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64url"),
      Buffer.from(JSON.stringify(["not", "an", "object"])).toString(
        "base64url",
      ),
      "signature",
    ].join(".");

    expect(() => decodeUnsafeJwtPayload(token)).toThrow(
      /payload must be a JSON object/i,
    );
  });

  it("should reject unsafe decoding when payload JSON is malformed", () => {
    const token = [
      Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64url"),
      Buffer.from("{not-json").toString("base64url"),
      "signature",
    ].join(".");

    expect(() => decodeUnsafeJwtPayload(token)).toThrow(
      /failed to decode JWT payload/i,
    );
  });

  it("should resolve symmetric key material from signingKey", () => {
    const material = resolveSigningMaterial("HS512", {
      signingKey: {
        type: "symmetric",
        secret: TEST_HMAC_SECRET,
      },
    });

    expect(material).toEqual({
      kind: "hmac",
      secret: TEST_HMAC_SECRET,
      algorithm: "HS512",
    });
  });

  it("should reject missing key material for signing", () => {
    expect(() => resolveSigningMaterial("HS256", {})).toThrow(
      /HMAC secret is required/i,
    );
    expect(() => resolveSigningMaterial("RS256", {})).toThrow(
      /asymmetric private key is required/i,
    );
  });

  it("should resolve asymmetric key material for RS256 signing", () => {
    const keys = generateRsaKeyPair();
    const material = resolveSigningMaterial("RS256", {
      signingKey: {
        type: "asymmetric",
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
      },
    });

    expect(material.kind).toBe("asymmetric");
    expect(material.algorithm).toBe("RS256");
  });

  it("should surface invalid asymmetric private keys during signing setup", () => {
    expect(() =>
      resolveSigningMaterial("RS256", {
        signingKey: {
          type: "asymmetric",
          privateKey: "not-a-private-key",
          publicKey: "not-a-public-key",
        },
      }),
    ).toThrow();
  });

  it("should throw TokenGenerationError for missing material failures", () => {
    expect(() => resolveSigningMaterial("HS256", {})).toThrow(
      TokenGenerationError,
    );
  });
});
