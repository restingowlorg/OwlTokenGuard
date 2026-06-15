import { createShowcaseApp } from "./app";

const port = Number(process.env.PORT ?? 3000);
const { app } = createShowcaseApp();

app.listen(port, () => {
  console.log(`Showcase API listening on http://localhost:${port}`);
  console.log("Try: POST /auth/login  { \"sub\": \"demo-user\" }");
});
