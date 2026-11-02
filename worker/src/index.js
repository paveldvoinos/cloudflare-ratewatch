// Worker entry point. The logic is in core.js (see the note there).
import { main, handleFetch } from "./core.js";

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(main(env, new Date(event.scheduledTime)));
  },
  fetch: handleFetch,
};
