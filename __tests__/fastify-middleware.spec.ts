import Fastify, { type FastifyInstance } from "fastify";
import supertest from "supertest";
import { createTokenManager } from "../src/factories/TokenManagerFactory";
import {
  fastifyVerifyToken,
  validateTokenPreHandler,
} from "../src/middlewares/fastify";
import { TEST_HMAC_SECRET } from "./helpers/keys";
import { buildSignedTestJwt } from "./helpers/jwt";

const managerConfig = {
  algorithm: "HS256" as const,
  hmacSecret: TEST_HMAC_SECRET,
  expiresInSeconds: 3600,
  allowedAlgorithms: ["HS256" as const],
};

async function createTestApp(
  middleware: ReturnType<typeof fastifyVerifyToken>,
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });

  app.get("/public", async () => ({ ok: true }));

  app.get(
    "/api/profile",
    { preHandler: middleware },
    async (request) => ({
      sub: request.auth?.payload.sub,
      jti: request.auth?.jti,
    }),
  );

  await app.ready();
  return app;
}

describe("fastifyVerifyToken middleware", () => {
  const manager = createTokenManager(managerConfig);
  let app: FastifyInstance;

  beforeEach(async () => {
    app = await createTestApp(
      fastifyVerifyToken(manager, { purpose: "access" }),
    );
  });

  afterEach(async () => {
    await app.close();
  });

  it("should allow public routes without a token", async () => {
    const response = await supertest(app.server).get("/public").expect(200);
    expect(response.body).toEqual({ ok: true });
  });

  it("should return 401 when Authorization header is missing", async () => {
    const response = await supertest(app.server).get("/api/profile").expect(401);
    expect(response.body.error).toBe("Unauthorized");
    expect(response.body.message).toMatch(/authorization header/i);
  });

  it("should return 401 when Bearer token is invalid", async () => {
    const response = await supertest(app.server)
      .get("/api/profile")
      .set("Authorization", "Bearer not-a-valid-jwt")
      .expect(401);

    expect(response.body.error).toBe("Unauthorized");
  });

  it("should return 401 when token signature is tampered", async () => {
    const issued = await manager.generateAccessToken({ sub: "user-1" });
    const tampered = `${issued.token.slice(0, -1)}x`;

    const response = await supertest(app.server)
      .get("/api/profile")
      .set("Authorization", `Bearer ${tampered}`)
      .expect(401);

    expect(response.body.error).toBe("Unauthorized");
  });

  it("should return 401 when token is expired", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = buildSignedTestJwt(managerConfig, {
      sub: "user-1",
      exp: now - 60,
    });

    const response = await supertest(app.server)
      .get("/api/profile")
      .set("Authorization", `Bearer ${expired}`)
      .expect(401);

    expect(response.body.message).toMatch(/expired/i);
  });

  it("should allow protected routes with a valid Bearer token", async () => {
    const issued = await manager.generateAccessToken({ sub: "user-42" });

    const response = await supertest(app.server)
      .get("/api/profile")
      .set("Authorization", `Bearer ${issued.token}`)
      .expect(200);

    expect(response.body).toEqual({
      sub: "user-42",
      jti: issued.claims.jti,
    });
  });

  it("should support validateTokenPreHandler alias", async () => {
    const aliasApp = await createTestApp(validateTokenPreHandler(manager));
    const issued = await manager.generateAccessToken({ sub: "alias-user" });

    const response = await supertest(aliasApp.server)
      .get("/api/profile")
      .set("Authorization", `Bearer ${issued.token}`)
      .expect(200);

    expect(response.body.sub).toBe("alias-user");
    await aliasApp.close();
  });
});
