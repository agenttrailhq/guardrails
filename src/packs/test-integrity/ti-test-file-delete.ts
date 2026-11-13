// cspell:words pytest testdata
import { QUOTED_MENTION, SHELL_AND_MCP, TEMP_DELETE } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** A delete command as its own word, then arguments that stay outside any quoted run. */
const DELETE = "(?:^|[\\s;&|(])(?:rm|unlink|git\\s+rm|remove-item)\\s(?:[^|;&\"']*\\s)?";

/** One path argument, never passing through a build, report or dependency directory. */
const PATH = "(?:(?!(?<=[\\s/])(?:dist|build|out|coverage|node_modules)/)[^\\s|;&\"'])*?";

/**
 * Deleting a test instead of fixing the code it tests.
 *
 * Matched by the test runners' own naming conventions, so a report or build directory that merely
 * contains the word `test` — `test-results/`, `coverage/`, a `dist/` bundle named `*.test.js` —
 * is left alone.
 */
export const tiTestFileDelete: Rule = {
  id: "ti.test-file-delete",
  category: "test-integrity",
  severity: "high",
  defaultAction: "require_approval",
  owasp: ["ASI09", "ASI10"],
  title: "Deleting a test file or test directory",
  description:
    "Holds a command that deletes a test: `rm`, `unlink`, `git rm` or PowerShell's `Remove-Item` naming a file that follows a test runner's naming convention — `*.test.*`, `*.spec.*`, `*_test.go`, `*_test.py`, `test_*.py` — or a `__tests__/`, `test/`, `tests/` or `spec/` directory, or a file inside one. Deleting the failing test instead of fixing the code leaves a suite that still passes. Deliberately NOT matched: build, report and dependency output — anything under `dist/`, `build/`, `out/`, `coverage/` or `node_modules/`, and `test-results/`, `playwright-report/` and `.pytest_cache` — and moving or staging a test (`mv`, `git add`). Also not held: one `rm`, `unlink` or `Remove-Item` whose every target is strictly inside the system temp folder (`/tmp`, `/private/tmp`, `/var/tmp`, the macOS per-user temp folder, `$TMPDIR`, `$TEMP`, `$TMP`), such as clearing a throwaway checkout; the bare temp folder, a `..` segment, a variable after the root, any other variable, a second target outside temp, and a chained second command are still held, and `git rm` is never exempt. Misses a test deleted with `find … -delete`, moved out of the tree, emptied or disabled with a file tool, and a test directory with any other name. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `${DELETE}${PATH}[._](?:test|spec)\\.[a-z0-9]+`,
          `${DELETE}${PATH}(?<=[\\s/])test_[\\w.-]*\\.py\\b`,
          `${DELETE}${PATH}(?<=[\\s/])(?:__tests__|tests?|spec)(?=[/\\s|;&]|$)`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION, TEMP_DELETE],
  },
  fixtures: {
    block: [
      bash("rm src/parser.test.ts"),
      bash("git rm src/__tests__/billing.test.ts"),
      bash("rm -rf src/__tests__"),
      bash("rm -rf tests/"),
      bash("rm test_billing.py"),
      bash("rm internal/parser/parser_test.go"),
      bash("git rm -r spec/models"),
      bash("unlink e2e/login.spec.ts"),
      bash("rm -f src/a.ts src/a.test.ts"),
      bash("rm src/test/java/com/example/BillingTest.java"),
      pwsh("Remove-Item -Recurse -Force tests"),
      // The temp exemption is narrow: each of these still holds.
      bash("rm -rf /tmp/review/../../srv/app/__tests__"),
      bash("rm -rf /tmp/$X/__tests__"),
      bash("rm -rf $SCRATCH/repo/__tests__"),
      bash("rm -rf $SCRATCHPAD/repo/tests"),
      bash("rm -rf /tmp/review/__tests__ src/__tests__"),
      bash("rm -rf /tmp/review/__tests__ && rm -rf src/__tests__"),
      bash("git rm -r /tmp/review/tests"),
    ],
    allow: [
      ...mentions("rm src/parser.test.ts"),
      bash("npm test"),
      bash("rm -rf test-results/"),
      bash("rm coverage/lcov-report/index.html"),
      bash("rm dist/parser.test.js"),
      bash("rm -rf node_modules/.vitest"),
      bash("rm -rf .pytest_cache playwright-report"),
      bash("git add src/foo.test.ts"),
      bash("mv src/a.test.ts src/b.test.ts"),
      bash("rm src/test-utils.ts"),
      bash("rm -rf testdata/tmp"),
      bash("rm attest_report.py"),
      // Clearing a throwaway checkout inside the system temp folder.
      bash("rm -rf /tmp/review-1182/src/__tests__"),
      bash("rm /private/tmp/agent-1/scratchpad/repo/src/parser.test.ts"),
      bash("rm -rf $TMPDIR/review/tests"),
      bash(`rm -rf \${TMPDIR}/review/spec`),
      bash("rm -rf /var/folders/zz/abc123/T/review/__tests__ /tmp/other/tests"),
      bash("unlink /var/tmp/run-7/e2e/login.spec.ts"),
      pwsh("Remove-Item -Recurse -Force $env:TEMP\\review\\tests"),
    ],
  },
};
