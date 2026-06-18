import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/mcp.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  // No sourcemaps in the published tarball: they'd embed the full TS source and
  // reference ../src paths that consumers don't have — dead weight that
  // undercuts the "tiny, zero-dep" pitch (ADR-0001).
  sourcemap: false,
  minify: false,
  target: "es2022",
  splitting: false,
});
