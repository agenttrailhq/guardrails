import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * FILED BY HARM, and this is the one assignment worth flagging rather than
 * letting a reviewer discover. Its harm is sensitive data reaching the world,
 * which is this pack's subject — but the pack's NAME reads as credentials, and
 * this rule is about PII. It is also the only rule here whose finding is
 * speculative: its own description concedes it cannot inspect the edit, so it is
 * a prompt to a reviewer rather than a detection. If `secret-exposure` is ever
 * read strictly as "credentials", this is the rule that moves.
 */
const SOURCE = "{ts,tsx,js,jsx,mjs,cjs,py,rb,go,php,java,cs,rs}";

export const requireAuthOnPiiEndpoints: Rule = {
  id: "require-auth-on-pii-endpoints",
  category: "secret-exposure",
  severity: "medium",
  defaultAction: "require_approval",
  title: "Review API endpoint changes for auth",
  description:
    "Routes edits to API route/handler SOURCE files to human approval so a reviewer can confirm authentication is present on new or changed endpoints. Matched by path: a source file under routes/, handlers/ or controllers/; an api/ directory nested inside a source tree (src/api/, app/api/, pages/api/); Next's route.ts convention; and the <name>.controller.* / <name>.routes.* spellings. HEURISTIC: a path signal only — it cannot inspect the edit for a missing auth check or exposed PII, so treat a match as confirm auth on this endpoint, not as a finding. It deliberately does NOT match every file in a package merely NAMED api, nor a client-side router table such as routes.tsx, which defines no endpoint; and it MISSES endpoints declared inline in a server file or by a framework convention not listed above.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: `**/routes/**/*.${SOURCE}` },
      { kind: "execute_tool", file_glob: `**/handlers/**/*.${SOURCE}` },
      { kind: "execute_tool", file_glob: `**/controllers/**/*.${SOURCE}` },
      { kind: "execute_tool", file_glob: `**/src/api/**/*.${SOURCE}` },
      { kind: "execute_tool", file_glob: `**/app/api/**/*.${SOURCE}` },
      { kind: "execute_tool", file_glob: "**/pages/api/**" },
      { kind: "execute_tool", file_glob: `**/route.${SOURCE}` },
      { kind: "execute_tool", file_glob: `**/*.controller.${SOURCE}` },
      { kind: "execute_tool", file_glob: `**/*.routes.${SOURCE}` },
    ],
  },
  fixtures: {
    block: [
      file("src/api/users.ts"),
      file("app/users/route.ts"),
      file("pages/api/session.ts"),
      file("src/controllers/payments.ts"),
    ],
    allow: [
      file("apps/api/README.md"),
      file("apps/api/package.json"),
      file("apps/api/src/lib/logger.ts"),
      file("apps/web/src/app/routes.tsx"),
    ],
  },
};
