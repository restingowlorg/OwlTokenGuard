import { createTokenManager } from "../src/factories/TokenManagerFactory";

describe("TokenManager.generate", () => {
  it("should reject until issuance is implemented", async () => {
    const manager = createTokenManager();
    await expect(manager.generate({ sub: "user-1" })).rejects.toThrow(
      /not implemented/i,
    );
  });
});
