import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The deploy commands whose own text says production. Every one of them has a
 * preview or staging sibling that must stay quiet, and those siblings are the
 * `allow` fixtures — a rule that fires on every preview deploy is a rule that
 * gets switched off before it ever sees a production one.
 */
export const piDeployToProd: Rule = {
  id: "pi.deploy-to-prod",
  category: "prod-infra",
  severity: "high",
  defaultAction: "require_approval",
  title: "A deploy command that names production",
  description:
    'Ships code to a production environment through a hosting CLI whose command text says so — `vercel --prod`, `netlify deploy --prod`, `serverless deploy --stage prod`, `fly deploy`, `eb deploy`, `wrangler deploy` and Capistrano\'s production task. The preview and staging siblings are deliberately NOT matched, because a rule that asks on every preview deploy is switched off before it ever sees a real one. It MISSES a deploy triggered by a git push, by CI, or by any script whose own text does not name the environment. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\bvercel\\b[^|;&]*--prod\\b",
          "\\bnetlify\\s+deploy\\b[^|;&]*--prod\\b",
          "\\bserverless\\s+deploy\\b[^|;&]*--stage[= ]\\s*prod",
          "\\bfly\\s+deploy\\b",
          "\\beb\\s+deploy\\b",
          "\\bwrangler\\s+(deploy|publish)\\b",
          "\\bcap\\s+production\\s+deploy\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("vercel --prod"),
      bash("netlify deploy --prod --dir=dist"),
      bash("npx serverless deploy --stage prod"),
      bash("fly deploy --remote-only"),
    ],
    allow: [
      ...mentions("vercel --prod"),
      bash("vercel deploy"),
      bash("netlify deploy --dir=dist"),
      bash("npx serverless deploy --stage dev"),
      bash("pnpm build"),
    ],
  },
};
