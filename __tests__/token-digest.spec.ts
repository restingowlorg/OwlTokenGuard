import { createTokenDigest } from "../src/utils/TokenDigest";

describe("createTokenDigest", () => {
  it("should create a deterministic SHA-256 digest without exposing the token", () => {
    const token = "header.payload.signature";
    const first = createTokenDigest(token);
    const second = createTokenDigest(token);

    expect(first).toBe(second);
    expect(first).toMatch(/^sha256:[A-Za-z0-9_-]+$/);
    expect(first).not.toContain(token);
  });

  it("should create a deterministic HMAC digest when pepper is provided", () => {
    const token = "header.payload.signature";
    const digest = createTokenDigest(token, {
      pepper: "application-held-digest-pepper",
    });

    expect(digest).toMatch(/^hmac-sha256:[A-Za-z0-9_-]+$/);
    expect(digest).toBe(
      createTokenDigest(token, {
        pepper: "application-held-digest-pepper",
      }),
    );
    expect(digest).not.toBe(createTokenDigest(token));
  });

  it("should reject empty token and pepper values", () => {
    expect(() => createTokenDigest("")).toThrow(/non-empty string/i);
    expect(() => createTokenDigest("token", { pepper: "" })).toThrow(
      /pepper must be non-empty/i,
    );
    expect(() =>
      createTokenDigest("token", { pepper: Buffer.alloc(0) }),
    ).toThrow(/pepper must be non-empty/i);
  });
});
