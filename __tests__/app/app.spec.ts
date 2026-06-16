import request from "supertest";
import { createShowcaseApp } from "./app";

describe("showcase app (library usage via API)", () => {
  const { app, sessionStore } = createShowcaseApp();

  beforeEach(() => {
    sessionStore.clear();
  });

  it("GET /health returns ok", async () => {
    const response = await request(app).get("/health").expect(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  it("POST /auth/login issues access and refresh tokens", async () => {
    const response = await request(app)
      .post("/auth/login")
      .send({ sub: "user-1", role: "admin" })
      .expect(200);

    expect(response.body.access_token).toMatch(
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    );
    expect(response.body.refresh_token).toMatch(
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    );
    expect(response.body.token_type).toBe("Bearer");
    expect(response.body.expires_in).toBe(900);
    expect(response.body.claims.jti).toEqual(expect.any(String));
  });

  it("GET /auth/me returns profile for a valid access token", async () => {
    const login = await request(app)
      .post("/auth/login")
      .send({ sub: "user-2", role: "viewer" })
      .expect(200);

    const response = await request(app)
      .get("/auth/me")
      .set("Authorization", `Bearer ${login.body.access_token}`)
      .expect(200);

    expect(response.body.sub).toBe("user-2");
    expect(response.body.jti).toBe(login.body.claims.jti);
    expect(response.body.payload.role).toBe("viewer");
  });

  it("GET /auth/me rejects missing bearer token", async () => {
    const response = await request(app).get("/auth/me").expect(401);
    expect(response.body.error).toBe("Unauthorized");
  });

  it("POST /auth/refresh rotates tokens and returns OAuth payload", async () => {
    const login = await request(app)
      .post("/auth/login")
      .send({ sub: "user-3" })
      .expect(200);

    const response = await request(app)
      .post("/auth/refresh")
      .send({ refresh_token: login.body.refresh_token })
      .expect(200);

    expect(response.body.access_token).not.toBe(login.body.access_token);
    expect(response.body.refresh_token).not.toBe(login.body.refresh_token);
    expect(response.body.token_type).toBe("Bearer");
    expect(response.body.expires_in).toBe(900);
  });

  it("POST /auth/refresh rejects reuse of the same refresh token", async () => {
    const login = await request(app)
      .post("/auth/login")
      .send({ sub: "user-4" })
      .expect(200);

    await request(app)
      .post("/auth/refresh")
      .send({ refresh_token: login.body.refresh_token })
      .expect(200);

    const response = await request(app)
      .post("/auth/refresh")
      .send({ refresh_token: login.body.refresh_token })
      .expect(401);

    expect(response.body.error_description).toMatch(
      /already been used|revoked/i,
    );
  });

  it("POST /auth/logout revokes refresh token and blocks further rotation", async () => {
    const login = await request(app)
      .post("/auth/login")
      .send({ sub: "user-5" })
      .expect(200);

    await request(app)
      .post("/auth/logout")
      .send({ refresh_token: login.body.refresh_token })
      .expect(204);

    const response = await request(app)
      .post("/auth/refresh")
      .send({ refresh_token: login.body.refresh_token })
      .expect(401);

    expect(response.body.error_description).toMatch(/revoked/i);
  });

  it("POST /auth/reference issues an opaque reference token", async () => {
    const response = await request(app).post("/auth/reference").expect(201);

    expect(response.body.referenceToken).toEqual(expect.any(String));
    expect(response.body.encoding).toEqual(expect.any(String));
    expect(response.body.entropyBits).toBeGreaterThanOrEqual(128);
  });

  it("POST /auth/generate issues JWT, refresh, and reference tokens", async () => {
    const response = await request(app)
      .post("/auth/generate")
      .send({ sub: "user-6" })
      .expect(201);

    expect(response.body.token).toMatch(
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    );
    expect(response.body.refresh_token).toMatch(
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    );
    expect(response.body.reference_token).toEqual(expect.any(String));
  });

  it("POST /auth/verify validates a token", async () => {
    const login = await request(app)
      .post("/auth/login")
      .send({ sub: "user-7" })
      .expect(200);

    const response = await request(app)
      .post("/auth/verify")
      .send({
        token: login.body.access_token,
        purpose: "access",
      })
      .expect(200);

    expect(response.body.valid).toBe(true);
    expect(response.body.jti).toBe(login.body.claims.jti);
    expect(response.body.payload.sub).toBe("user-7");
  });

  it("POST /auth/terminate revokes a session by jti", async () => {
    const login = await request(app)
      .post("/auth/login")
      .send({ sub: "user-8" })
      .expect(200);

    await request(app)
      .post("/auth/terminate")
      .send({ jti: login.body.refresh_claims.jti })
      .expect(204);

    const response = await request(app)
      .post("/auth/refresh")
      .send({ refresh_token: login.body.refresh_token })
      .expect(401);

    expect(response.body.error_description).toMatch(/revoked/i);
  });
});
