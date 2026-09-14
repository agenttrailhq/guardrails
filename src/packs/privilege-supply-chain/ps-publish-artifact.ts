// cspell:words bmvn

import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Publishing. Once a version is on a registry it is, for practical purposes,
 * permanent and other people's builds will fetch it — which makes this the one
 * action in the pack whose blast radius is outside the machine entirely.
 */
export const psPublishArtifact: Rule = {
  id: "ps.publish-artifact",
  category: "privilege-supply-chain",
  severity: "high",
  defaultAction: "require_approval",
  title: "Publishing an artifact to a public registry",
  description:
    'Holds a publish — npm, PyPI via twine or poetry, crates.io, RubyGems, a Docker registry, a GitHub release, or a Maven deploy. Once a version is out it is effectively permanent and other people\'s builds will fetch it, which makes this the one action in the pack whose blast radius is outside the machine. The dry runs and local builds are deliberately NOT matched (`npm pack`, `cargo package`, `docker build`, `gh release list`). It cannot tell a private registry from a public one. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\bnpm\\s+publish\\b",
          "\\btwine\\s+upload\\b",
          "\\bpoetry\\s+publish\\b",
          "\\bcargo\\s+publish\\b",
          "\\bgem\\s+push\\b",
          "\\bdocker\\s+push\\b",
          "\\bgh\\s+release\\s+create\\b",
          "\\bmvn\\b[^|;&]*\\sdeploy\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("npm publish --access public"),
      bash("twine upload dist/*"),
      bash("docker push registry.example.com/app:1.2.3"),
      bash("gh release create v1.2.3"),
    ],
    allow: [
      ...mentions("npm publish --access public"),
      bash("npm pack"),
      bash("cargo package"),
      bash("docker build -t app ."),
      bash("gh release list"),
    ],
  },
};
