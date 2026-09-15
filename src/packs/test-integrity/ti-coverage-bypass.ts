// cspell:words nycrc pytest
import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** The end of a flag: whitespace, a shell separator, or the end of the command. */
const END = "(?=[\\s|;&]|$)";

/**
 * A test run told to pass with nothing to check, or with its coverage gate off.
 *
 * `--check-coverage` alone is deliberately absent: in nyc and c8 it turns the gate ON.
 */
export const tiCoverageBypass: Rule = {
  id: "ti.coverage-bypass",
  category: "test-integrity",
  severity: "medium",
  defaultAction: "warn",
  title: "Passing a test run with no tests or no coverage gate",
  description:
    "Warns on a test run told to pass with nothing to check, or with its coverage gate off: `--passWithNoTests` (Jest, Vitest), pytest-cov's `--no-cov` and `--cov-fail-under=0`, `--coverage=false`, `--collectCoverage=false`, `--coverage.enabled=false` and `--no-coverage`, nyc's and c8's `--check-coverage=false` and `--no-check-coverage`, and a Vitest coverage threshold set to 0 on the command line. Each turns a check that would fail into one that reports success. A warning, not a hold: running without coverage locally is common. Deliberately NOT matched: `--no-cov-on-fail`, `--check-coverage` on its own, which makes the gate stricter, and a non-zero threshold. Misses a threshold lowered to any other number, a gate switched off in a config file (`ti.test-config-edit` holds the dedicated ones), and a coverage step removed from a CI workflow (`fs.ci-definition` holds those files). A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          `\\s--pass-?with-?no-?tests(?:=true)?${END}`,
          `\\s--no-cov${END}`,
          "\\s--cov-fail-under(?:=|\\s+)0(?![\\d.])",
          "\\s--(?:coverage(?:\\.enabled)?|collect-?coverage)=false\\b",
          `\\s--no-coverage${END}`,
          "\\s--(?:no-check-coverage|check-coverage=false)\\b",
          "\\s--coverage\\.thresholds\\.(?:lines|functions|branches|statements)(?:=|\\s+)0(?![\\d.])",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("npx jest --passWithNoTests"),
      bash("vitest run --pass-with-no-tests"),
      bash("pytest --no-cov"),
      bash("pytest --cov=src --cov-fail-under=0"),
      bash("npx jest --coverage=false"),
      bash("npx jest --collectCoverage=false"),
      bash("vitest run --coverage.enabled=false"),
      bash("vitest run --no-coverage"),
      bash("nyc --check-coverage=false npm test"),
      bash("c8 --no-check-coverage node test.js"),
      bash("vitest run --coverage.thresholds.lines 0"),
      pwsh("npx jest --passWithNoTests"),
    ],
    allow: [
      ...mentions("npx jest --passWithNoTests"),
      bash("npm test"),
      bash("vitest run --coverage"),
      bash("pytest --cov=src --cov-fail-under=80"),
      bash("pytest --no-cov-on-fail"),
      bash("c8 --check-coverage npm test"),
      bash("npx jest --ci"),
      bash("npx jest --passWithNoTests=false"),
      bash("vitest run --coverage.thresholds.lines 80"),
    ],
  },
};
