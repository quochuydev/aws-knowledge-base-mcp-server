import * as ai from "./ai";

ai.retrieve().catch((err) => {
  console.error(err);
  process.exit(1);
});
