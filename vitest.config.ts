import { defineProject } from "vitest/config";

export default defineProject({
  test: {
    name: "guardrails",
    include: ["__tests__/**/*.test.ts"],
    passWithNoTests: true,
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts"],
      thresholds: {
        lines: 80,
        branches: 80,
      },
    },
  },
});
