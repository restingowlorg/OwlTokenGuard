import { ReferenceTokenGenerator } from "../src/generators/ReferenceTokenGenerator";
import { SecurityConfigurationError } from "../src/errors/SecurityConfigurationError";

describe("ReferenceTokenGenerator", () => {
  const generator = new ReferenceTokenGenerator();

  it("should generate base64url tokens with at least 128 bits of entropy", () => {
    const result = generator.generate({ encoding: "base64url" });
    expect(result.encoding).toBe("base64url");
    expect(result.entropyBits).toBeGreaterThanOrEqual(128);
    expect(result.token.length).toBeGreaterThan(0);
  });

  it("should generate UUIDv4 formatted tokens", () => {
    const result = generator.generate({ encoding: "uuidv4" });
    expect(result.token).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it("should reject entropy below 128 bits", () => {
    expect(() => generator.generate({ entropyBits: 64 })).toThrow(
      SecurityConfigurationError,
    );
  });

  it("should produce unique non-sequential tokens", () => {
    const tokens = new Set(
      Array.from({ length: 100 }, () => generator.generate().token),
    );
    expect(tokens.size).toBe(100);
  });
});
