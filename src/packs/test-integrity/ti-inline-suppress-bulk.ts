// cspell:words nocheck noqa pytest xdescribe xtest
import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { MatchCondition, Rule } from "../../schema.js";

/** `sed` with an in-place flag before its script, then the rest of the line. */
const SED = "(?:^|[\\s;&|(])sed\\s(?:[^|;&\"']*\\s)?(?:-[a-z]*i|--in-place)\\S*\\s.*?";

/** `perl` with an in-place flag (`-i`, `-pi`, `-i.bak`) before its script, then the rest of the line. */
const PERL = "(?:^|[\\s;&|(])perl\\s(?:[^|;&\"']*\\s)?-[a-z0-9]*i\\S*\\s.*?";

/** Type-checker and linter suppressions. */
const TS_LINT = "(?:@ts-(?:ignore|expect-error|nocheck)|eslint-disable)";

/** Python type-checker, linter and coverage suppressions. */
const PYTHON = "(?:type:\\s*ignore|\\bnoqa\\b|pragma:\\s*no\\s+(?:cover|branch))";

/** Skipped tests across JavaScript, Python, Rust and Go. */
const SKIP =
  "(?:\\b(?:it|test|describe|context|suite)\\.skip\\b|\\bx(?:it|describe|test|context)\\b|@pytest\\.mark\\.skip|#\\[ignore|\\bt\\.skip(?:now|f)?\\()";

/** A `/pattern/d` script: deleting the lines that carry a marker, which removes suppressions. */
const DELETE_LINES: MatchCondition = {
  kind: "execute_tool",
  detail_matches: [
    "\\s['\"]?/[^/'\"]*(?:@ts-|eslint-disable|noqa|type:|pragma:|\\.skip|#\\[ignore)[^/'\"]*/d['\"]?(?=[\\s|;&]|$)",
  ],
};

/**
 * One in-place edit that silences a type error, a lint rule or a failing test across a file or many.
 *
 * The Edit tool carries no content, so a suppression inserted that way is not seen. Only the shell
 * route is, because the script is part of the command.
 */
export const tiInlineSuppressBulk: Rule = {
  id: "ti.inline-suppress-bulk",
  category: "test-integrity",
  severity: "medium",
  defaultAction: "warn",
  title: "Inserting suppressions or test skips with sed or perl",
  description:
    "Warns on an in-place `sed` or `perl` edit whose script contains a suppression or skip marker: `@ts-ignore`, `@ts-expect-error`, `@ts-nocheck`, `eslint-disable`, `# type: ignore`, `# noqa`, `# pragma: no cover`, `it.skip` / `test.skip` / `describe.skip`, `xit` / `xdescribe` / `xtest`, `@pytest.mark.skip`, Rust's `#[ignore]` and Go's `t.Skip`. One such command can silence a type error, a lint rule or a failing test across many files at once. It matches the in-place flag (`-i`, `-i.bak`, `-Ei`, `--in-place`, `perl -pi`) followed by a script naming a marker. It cannot parse the script, so it does not tell a replacement that inserts a marker from one that removes it, except the `/…/d` delete-line form, which is deliberately NOT matched; neither are `sed -n` and `perl -ne`, which only print. Misses a marker added with a file tool — the Edit tool carries no content — an in-place flag written after the script, and a marker assembled from pieces. Over-matches `perl -I<dir>`, which the case-insensitive match reads as `-i`. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          `${SED}${TS_LINT}`,
          `${SED}${PYTHON}`,
          `${SED}${SKIP}`,
          `${PERL}${TS_LINT}`,
          `${PERL}${PYTHON}`,
          `${PERL}${SKIP}`,
        ],
      },
    ],
    none_of: [DELETE_LINES, ...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("sed -i 's/^describe(/describe.skip(/' src/parser.test.ts"),
      bash("sed -i '1i // @ts-nocheck' src/legacy.ts"),
      bash("sed -i 's/$/  # noqa/' app/views.py"),
      bash("sed -i '' 's|^import|// eslint-disable-next-line import|' src/index.ts"),
      bash("sed -Ei '/^def test_/i @pytest.mark.skip' tests/test_api.py"),
      bash("sed -i 's/#[[]test[]]/#[test] #[ignore]/' src/lib.rs"),
      bash("perl -pi -e 's/ it[(]/ it.skip(/g' test/api.test.js"),
      bash("perl -i -pe 's/$/  # type: ignore/' src/models.py"),
    ],
    allow: [
      ...mentions("sed -i s/^describe(/describe.skip(/ src/parser.test.ts"),
      bash("sed -i 's/foo/bar/g' src/index.ts"),
      bash("sed -n '/@ts-ignore/p' src/index.ts"),
      bash("sed -i '/@ts-ignore/d' src/index.ts"),
      bash("perl -ne 'print if /noqa/' app/views.py"),
      bash("sed -i 's/process.exit(1)/process.exit(0)/' bin/cli.js"),
      bash("sed -i 's/timeout: 5000/timeout: 10000/' vitest.config.ts"),
    ],
  },
};
