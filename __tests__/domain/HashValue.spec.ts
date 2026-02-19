import { HashValue } from "../../src/domain/HashValue";

describe("HashValue (Buffer-based)", () => {
  const value = Buffer.from("hashed-data");
  const salt = Buffer.from("random-salt");

  it("should create a HashValue instance with valid buffers", () => {
    const hash = new HashValue(value, salt);

    expect(hash.value).toBeInstanceOf(Buffer);
    expect(hash.salt).toBeInstanceOf(Buffer);

    expect(hash.value).toEqual(value);
    expect(hash.salt).toEqual(salt);
  });

  it("should preserve buffer content correctly", () => {
    const hash = new HashValue(value, salt);

    expect(hash.value.toString()).toBe("hashed-data");
    expect(hash.salt.toString()).toBe("random-salt");
  });

  it("should allow empty buffers if intended", () => {
    const emptyBuffer = Buffer.alloc(0);
    const hash = new HashValue(emptyBuffer, emptyBuffer);

    expect(hash.value.length).toBe(0);
    expect(hash.salt.length).toBe(0);
  });

  it("should keep buffer references consistent", () => {
    const hash = new HashValue(value, salt);

    expect(hash.value).toBe(value);
    expect(hash.salt).toBe(salt);
  });
});
