import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * FILED BY HARM, not by matcher. It is a `file_glob` rule and `file-scope` is a
 * pack, but what it protects is PRODUCTION, not a path — and a user who turned
 * off `file-scope` to stop path noise would otherwise silently lose their
 * production-config protection, which they never asked to turn off and would
 * not know they had.
 *
 * The read tools are excluded by NAMING them in `none_of` rather than by listing
 * the write tools in `any_of`. The guard's mapper routes several file tools to
 * this channel and an unknown tool carrying a `file_path` reaches it too, so a
 * write allow-list would let a new write tool through unseen; a read deny-list
 * leaves an unknown tool matched, which is the safe direction.
 */
export const blockProdConfigEdit: Rule = {
  id: "block-prod-config-edit",
  category: "prod-infra",
  severity: "high",
  defaultAction: "require_approval",
  title: "Approve production config edits",
  description:
    "Routes edits to production configuration files to human approval. Matched by path: `*.prod.*` and `*.production.*`, the bare `prod.*` / `production.*` spellings, and any file under a `prod/` or `production/` directory. Reading is excluded — the `Read` and `Grep` tools never match — so opening a production config to look at it does not ask for approval; every other file tool does, including one this corpus does not know. Prose is excluded too — `.md`, `.mdx` and `.txt` never match — so writing a runbook under `docs/production/` does not ask for approval to change production. It matches the PATH only: it cannot tell a real production config from a file that merely spells prod in its name, and it MISSES a production config named something else entirely, such as `values-live.yaml`.",
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
      // A read is not an edit. Named as a deny-list rather than an `any_of` over
      // the write tools, so an unknown file tool on a matched path still holds.
      { kind: "execute_tool", label: "{Read,Grep}" },
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
      file("config/database.prod.yml", "Read"),
      file("k8s/production/deployment.yaml", "Grep"),
    ],
  },
};
