import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * FILED BY HARM, not by matcher. It is a `file_glob` rule and `file-scope` is a
 * pack, but what it protects is PRODUCTION, not a path — and a user who turned
 * off `file-scope` to stop path noise would otherwise silently lose their
 * production-config protection, which they never asked to turn off and would
 * not know they had.
 *
 * File rules carry no `label`: the guard's mapper routes five file tools to this
 * channel and an unknown tool carrying a `file_path` reaches it too, so a
 * label list is a list that rots.
 */
export const blockProdConfigEdit: Rule = {
  id: "block-prod-config-edit",
  category: "prod-infra",
  severity: "high",
  defaultAction: "require_approval",
  title: "Approve production config edits",
  description:
    "Routes edits to production configuration files to human approval. Matched by path: `*.prod.*` and `*.production.*`, the bare `prod.*` / `production.*` spellings, and any file under a `prod/` or `production/` directory. Prose is excluded — `.md`, `.mdx` and `.txt` never match — so writing a runbook under `docs/production/` does not ask for approval to change production. It matches the PATH only: it cannot tell a real production config from a file that merely spells prod in its name, and it MISSES a production config named something else entirely, such as `values-live.yaml`.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/*.prod.*" },
      { kind: "execute_tool", file_glob: "**/prod.*" },
      { kind: "execute_tool", file_glob: "**/*.production.*" },
      { kind: "execute_tool", file_glob: "**/production.*" },
      { kind: "execute_tool", file_glob: "**/prod/**" },
      { kind: "execute_tool", file_glob: "**/production/**" },
    ],
    none_of: [
      { kind: "execute_tool", file_glob: "**/*.md" },
      { kind: "execute_tool", file_glob: "**/*.mdx" },
      { kind: "execute_tool", file_glob: "**/*.txt" },
    ],
  },
  fixtures: {
    block: [
      file("config/database.prod.yml"),
      file("config/prod.yml"),
      file("infra/prod.tfvars"),
      file("src/prod.ts"),
      file("k8s/production/deployment.yaml", "Write"),
    ],
    allow: [
      file("docs/production/README.md"),
      file("config/database.dev.yml"),
      file("src/index.ts"),
      file("package.json"),
    ],
  },
};
