// cspell:words azpipelines azurepipelines
import { HTTP_BODY_MENTION, PRINT_MENTION, SEARCH_MENTION } from "../../exemptions.js";
import { bash, mentionInEcho, mentionInPost, mentionInSearch, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** `git commit` as its own word, then anything up to the marker, across lines for a heredoc message. */
const COMMIT = "(?:^|[\\s;&|(])git\\s+commit\\b[\\s\\S]*?";

/**
 * A commit or push that tells CI not to run.
 *
 * The hosting site reads the marker from the commit message itself, so a message that QUOTES
 * `[skip ci]` skips CI just the same. That is why `git commit` is not an exempt carrier here.
 */
export const tiCiSkipMarker: Rule = {
  id: "ti.ci-skip-marker",
  category: "test-integrity",
  severity: "medium",
  defaultAction: "warn",
  title: "Telling CI to skip a commit or push",
  description:
    "Warns on a commit or push that tells CI not to run: a `git commit` whose message carries `[skip ci]`, `[ci skip]`, `[no ci]`, `[skip actions]`, `[actions skip]`, Azure Pipelines' `[skip azp]` family or `***NO_CI***`, or a `skip-checks: true` trailer, and `git push -o ci.skip` / `--push-option=ci.skip`. GitHub Actions, GitLab, Azure Pipelines, CircleCI and Bitbucket each honour some of these, in any letter case, so the change lands with no check run against it. Deliberately NOT matched: `skip-checks: false`, near misses such as `[ci-skip]` or `[skip deploy]`, other push options, and a commit message that only names `git push -o ci.skip`. Misses a message read from a file (`git commit -F msg.txt`), a marker added when a pull request is merged on the hosting site, and a push option set in git config. A quoted MENTION is not a use: a search, an `echo` or a `curl --data` body that only names this command is left alone, as long as every shell metacharacter stays inside the quotes. `git commit` is NOT one of those carriers here: the marker is read from the commit message, so a message that quotes `[skip ci]` does skip CI and still warns.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          `${COMMIT}\\[(?:skip\\s+ci|ci\\s+skip|no\\s+ci|skip\\s+actions|actions\\s+skip)\\]`,
          `${COMMIT}\\[(?:skip\\s+(?:azp|azpipelines|azurepipelines)|(?:azp|azpipelines|azurepipelines)\\s+skip)\\]`,
          `${COMMIT}(?:\\*\\*\\*NO_CI\\*\\*\\*|skip-checks:\\s*true\\b)`,
          "(?:^|[;&|(]\\s*)git\\s+push\\b[^|;&]*?\\s(?:-o\\s*|--push-option(?:=|\\s+))ci\\.skip\\b",
        ],
      },
    ],
    none_of: [SEARCH_MENTION, PRINT_MENTION, HTTP_BODY_MENTION],
  },
  fixtures: {
    block: [
      bash('git commit -m "chore: bump version [skip ci]"'),
      bash('git commit -am "[ci skip] regenerate fixtures"'),
      bash('git commit -m "wip [no ci]"'),
      bash('git commit -m "docs: typo [skip actions]"'),
      bash('git commit -m "[SKIP CI] release"'),
      bash('git commit -m "update lockfile" -m "skip-checks: true"'),
      bash('git commit -m "***NO_CI*** sync"'),
      bash('git commit -m "tidy [skip azp]"'),
      bash("git commit -F - <<'EOF'\nchore: format\n\n[skip ci]\nEOF"),
      bash('git add -A && git commit -m "lint [ci skip]" && git push'),
      bash("git push -o ci.skip origin main"),
      bash("git push --push-option=ci.skip origin feature/x"),
      pwsh('git commit -m "chore: bump version [skip ci]"'),
    ],
    allow: [
      mentionInSearch("git commit -m chore: bump version [skip ci]"),
      mentionInEcho("git commit -m chore: bump version [skip ci]"),
      mentionInPost("git commit -m chore: bump version [skip ci]"),
      bash('git commit -m "Skip the flaky CI job on forks"'),
      bash('git commit -m "fix [ci-skip] parsing"'),
      bash('git commit -m "chore: [skip deploy]"'),
      bash('git commit -m "ci: set skip-checks: false"'),
      bash('git commit -m "docs: explain git push -o ci.skip"'),
      bash('git log --grep "[skip ci]"'),
      bash("git push -o merge_request.create origin feature/x"),
      bash("git push origin main"),
      bash("git commit --amend --no-edit"),
    ],
  },
};
