import { bash } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

export const wtDemoContributionCheck: Rule = {
  id: "wt.demo-contribution-check",
  category: "working-tree",
  severity: "low",
  defaultAction: "warn",
  owasp: ["ASI02"],
  title: "A demo command used to check the contribution path",
  description:
    "Matches one made-up command string. It exists only to check how a guardrail travels from add to a pull request, and it does not match anything real.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "Bash",
        detail_matches: ["\\bdemo-contribution-check\\b"],
      },
    ],
  },
  fixtures: {
    block: [bash("demo-contribution-check --now")],
    allow: [bash("demo-contribution-checker")],
  },
};
