import { ReferenceTokenGenerator } from "../src/generators/ReferenceTokenGenerator";

describe("ReferenceTokenGenerator", () => {
  it("should reject until opaque token generation is implemented", () => {
    const generator = new ReferenceTokenGenerator();
    expect(() => generator.generate()).toThrow(/not implemented/i);
  });
});
