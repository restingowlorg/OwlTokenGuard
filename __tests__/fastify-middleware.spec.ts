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

  app.get("/api/profile", { preHandler: middleware }, async (request) => ({
    sub: request.auth?.payload.sub,
    jti: request.auth?.jti,
  }));

  await app.ready();
  return app;
}

describe("fastifyVerifyToken middleware", () => {
  const manager = createTokenManager(managerConfig);
  let app: FastifyInstance;

  beforeEach(async () => {
    app = await createTestApp(
      fastifyVerifyToken(manager, {
        purpose: "access",
        // continueHook is not needed for Fastify to work
        onVerified: async (_result, _request, _reply) => {
          // if needed, add additional validation here
        },
      }),
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
    const response = await supertest(app.server)
      .get("/api/profile")
      .expect(401);
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

  // --- new custom options tests ---

  it("should support a custom extractToken function", async () => {
    const customExtractApp = await createTestApp(
      fastifyVerifyToken(manager, {
        extractToken: (request) => {
          return request.headers["x-custom-token"] as string;
        },
      }),
    );

    const issued = await manager.generateAccessToken({
      sub: "custom-token-user",
    });

    // we can verify the token with Bearer token
    await supertest(customExtractApp.server)
      .get("/api/profile")
      .set("Authorization", `Bearer ${issued.token}`)
      .expect(401);

    // we can verify the token with x-custom-token header
    const response = await supertest(customExtractApp.server)
      .get("/api/profile")
      .set("x-custom-token", issued.token)
      .expect(200);

    expect(response.body.sub).toBe("custom-token-user");
    await customExtractApp.close();
  });

  it("should allow onVerified to intercept and send an early response", async () => {
    const interceptApp = await createTestApp(
      fastifyVerifyToken(manager, {
        // Fastify style: onVerified should be async function
        onVerified: async (auth, _continueHook, _request, reply) => {
          if (auth.payload.sub === "banned-user") {
            return reply
              .status(403)
              .send({ error: "Forbidden", message: "User is banned" });
          }
        },
      }),
    );

    const issued = await manager.generateAccessToken({ sub: "banned-user" });

    const response = await supertest(interceptApp.server)
      .get("/api/profile")
      .set("Authorization", `Bearer ${issued.token}`)
      .expect(403);

    expect(response.body.error).toBe("Forbidden");
    expect(response.body.message).toBe("User is banned");

    await interceptApp.close();
  });

  it("should throw standard 401 if onVerified throws a standard Error", async () => {
    const throwingApp = await createTestApp(
      fastifyVerifyToken(manager, {
        onVerified: async () => {
          throw new Error("Database disconnected during validation");
        },
      }),
    );

    const issued = await manager.generateAccessToken({ sub: "user-1" });

    const response = await supertest(throwingApp.server)
      .get("/api/profile")
      .set("Authorization", `Bearer ${issued.token}`)
      .expect(500);

    expect(response.body.message).toMatch(/Database disconnected/);

    await throwingApp.close();
  });
});
