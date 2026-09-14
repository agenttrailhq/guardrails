import { defineConfig } from "tsup";

/**
 * Emits ESM and CJS bundles plus `.d.ts` for each entry point.
 *
 * There is deliberately no `noExternal`: `zod` is the only dependency and stays
 * external.
 */
export default defineConfig({
  entry: {
    index: "src/index.ts",
    // The zod-free corpus entry the guard bundles, published as the `./guardrails`
    // subpath. Its own entry, not a re-export of `index`, so the emitted
    // `dist/guardrails.js` genuinely carries no validator — see `src/rules.ts` and
    // `guard/src/__tests__/built-artifact.test.ts`.
    //
    // The KEY names the artifact, the value names the source. They differ on purpose:
    // The rename moved the published subpath, and put source file names out of
    // scope, so `src/rules.ts` emits `dist/guardrails.*`. Renaming the key without the
    // manifest (or the reverse) is what `release-public.sh`'s R8 catches — it asserts
    // every `exports` target actually exists in the packed tarball.
    guardrails: "src/rules.ts",
    schema: "src/schema.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  target: "node18",
  platform: "neutral",
  shims: false,
});
