import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

export const blockEnvFileRead: Rule = {
  id: "block-env-file-read",
  category: "secret-exposure",
  severity: "high",
  defaultAction: "warn",
  title: "Flag reading a .env file",
  description:
    "Warns when a file tool READS a dotenv file — the `Read` and `Grep` tools — at both the `.env*` spelling at any depth and the `<name>.env` spelling (production.env, secrets.env). A WRITE is deliberately NOT flagged (`Edit`, `Write`, `MultiEdit`, `NotebookEdit`, and Cursor's `Delete`), because creating or editing config is ordinary work and the exposure this catches is an agent reading an existing secret, so the id names the read. A committed placeholder is NOT flagged either (.env.example, .env.sample, .env.template), because warning on a file that holds no secret teaches the reader to ignore the warning. Matches file-tool access by path: reading a .env through a shell command such as `cat .env` is a command span and is covered by se.env-print instead. It also cannot tell whether the file actually contains a secret.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/.env*" },
      { kind: "execute_tool", file_glob: "**/*.env" },
    ],
    none_of: [
      { kind: "execute_tool", label: "{Edit,Write,MultiEdit,NotebookEdit,Delete}" },
      { kind: "execute_tool", file_glob: "**/*.example" },
      { kind: "execute_tool", file_glob: "**/*.sample" },
      { kind: "execute_tool", file_glob: "**/*.template" },
      { kind: "execute_tool", file_glob: "**/*.example.*" },
    ],
  },
  fixtures: {
    block: [
      file(".env", "Read"),
      file("config/.env.production", "Read"),
      file("config/production.env", "Read"),
      file("apps/api/.env.local", "Read"),
    ],
    allow: [
      file(".env.example", "Read"),
      file(".env.sample", "Read"),
      file("apps/api/.env.local", "Edit"),
      file(".env", "Write"),
      file("src/index.ts"),
      file("package.json"),
    ],
  },
};
