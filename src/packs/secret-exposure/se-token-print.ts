// cspell:words netrc

import {
  GIT_TEXT_MENTION,
  HTTP_BODY_MENTION,
  LEADING_FLAGS,
  SEARCH_MENTION,
  SHELL_AND_MCP,
} from "../../exemptions.js";
import { bash, mentionInCommit, mentionInPost, mentionInSearch } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Printing a token, rather than reading one from a manager. `gh auth status`
 * (which prints whether you are logged in) sits one word away from `gh auth
 * token` (which prints the token), and that pair is the whole rule.
 */
export const seTokenPrint: Rule = {
  id: "se.token-print",
  category: "secret-exposure",
  severity: "medium",
  defaultAction: "warn",
  title: "Printing an access token into the terminal",
  description:
    'Surfaces a command that prints a live credential — `gh auth token`, `npm token list`, an `echo` of a token-shaped variable, a `docker login` with the password on the command line, or a `.netrc` dump. Non-blocking, because seeing your own token is sometimes exactly what you need. The status siblings are deliberately NOT matched (`gh auth status`, `npm whoami`). It cannot tell whether the output is redirected, and it does NOT match a variable whose name does not contain token, secret, key or password. Global flags between `npm`/`docker` and the subcommand are tolerated (`npm --silent token list`, `docker --context <name> login …`), and an absolute tool path still matches; `gh` has no global flag before its subcommand, and a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt. `echo` is NOT one of those carriers here, because this rule\'s own trigger IS an `echo`: printing a quoted `$TOKEN` still warns.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\bgh\\s+auth\\s+token\\b",
          `\\bnpm${LEADING_FLAGS}\\s+token\\s+list\\b`,
          "\\becho\\s+[\"']?\\$\\{?[a-z_]*(token|secret|password|api_key)\\b",
          `\\bdocker${LEADING_FLAGS}\\s+login\\b[^|;&]*(-p|--password)\\s`,
          "\\bcat\\s+[^|;&]*\\.netrc\\b",
        ],
      },
    ],
    none_of: [SEARCH_MENTION, GIT_TEXT_MENTION, HTTP_BODY_MENTION],
  },
  fixtures: {
    block: [
      bash("gh auth token"),
      bash("echo $GITHUB_TOKEN"),
      bash("npm token list"),
      bash("cat ~/.netrc"),
      bash("npm --silent token list"),
      bash("docker --context prod login -p secret registry.example.com"),
    ],
    allow: [
      mentionInCommit("gh auth token"),
      mentionInSearch("gh auth token"),
      mentionInPost("gh auth token"),
      bash("gh auth status"),
      bash("npm whoami"),
      bash("echo $NODE_ENV"),
      bash("gh pr list --limit 20"),
    ],
  },
};
