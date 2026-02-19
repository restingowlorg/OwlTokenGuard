import { CipherText } from "../../src/domain/CipherText";

describe("CipherText (Buffer-based)", () => {
  const value = Buffer.from("encrypted-data");
  const iv = Buffer.from("123456789012");
  const authTag = Buffer.from("auth-tag-data");

  it("should create a CipherText instance with valid buffers", () => {
    const cipher = new CipherText(value, iv, authTag);

    expect(cipher.value).toBeInstanceOf(Buffer);
    expect(cipher.iv).toBeInstanceOf(Buffer);
    expect(cipher.authTag).toBeInstanceOf(Buffer);

    expect(cipher.value).toEqual(value);
    expect(cipher.iv).toEqual(iv);
    expect(cipher.authTag).toEqual(authTag);
  });

  it("should preserve buffer content correctly", () => {
    const cipher = new CipherText(value, iv, authTag);

    expect(cipher.value.toString()).toBe("encrypted-data");
    expect(cipher.iv.toString()).toBe("123456789012");
    expect(cipher.authTag.toString()).toBe("auth-tag-data");
  });

  it("should allow empty buffers (if intentionally permitted)", () => {
    const emptyBuffer = Buffer.alloc(0);
    const cipher = new CipherText(emptyBuffer, emptyBuffer, emptyBuffer);

    expect(cipher.value.length).toBe(0);
    expect(cipher.iv.length).toBe(0);
    expect(cipher.authTag.length).toBe(0);
  });

  it("should keep buffer references consistent", () => {
    const cipher = new CipherText(value, iv, authTag);

    expect(cipher.value).toBe(value);
    expect(cipher.iv).toBe(iv);
    expect(cipher.authTag).toBe(authTag);
  });
});
