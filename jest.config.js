/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["**/__tests__/**/*.spec.ts"],
  clearMocks: true,
  resetMocks: true,
  watchman: false,
};
