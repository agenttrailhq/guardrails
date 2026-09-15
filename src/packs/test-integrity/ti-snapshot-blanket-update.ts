// cspell:words insta pytest syrupy
import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** Arguments that stay outside any quoted run, ending in whitespace. */
const ARGS = "\\s(?:[^|;&\"']*\\s)?";

/**
 * The update flag, bare or with a value that still rewrites existing snapshots. `=new`, `=none`,
 * `=missing` and `=false` only add snapshots or change nothing, and are not matched.
 */
const UPDATE = "(?:-u|--update(?:-?snapshots?)?)(?:=(?:all|changed|true))?(?=[\\s|;&]|$)";

/**
 * Accepting every snapshot difference at once.
 *
 * A snapshot that no longer matches is a failing test. This is the command that makes all of them
 * pass without anyone reading the differences.
 */
export const tiSnapshotBlanketUpdate: Rule = {
  id: "ti.snapshot-blanket-update",
  category: "test-integrity",
  severity: "medium",
  defaultAction: "warn",
  title: "Overwriting every stored snapshot with current output",
  description:
    "Warns on a test run told to overwrite stored snapshots with whatever the code produces now: Jest's `-u` / `--updateSnapshot`, Vitest's `-u` / `--update`, Playwright's and Bun's `--update-snapshots`, the same flags passed through `npm test`, `pnpm test` or `yarn test`, pytest's `--snapshot-update` (syrupy and pytest-snapshot), `cargo insta accept`, `cargo insta test --accept`, and `INSTA_UPDATE=always`. A snapshot that no longer matches is a failing test, and accepting every difference at once makes it pass without anyone reading the diff. A warning, not a hold: regenerating snapshots after an intended change is ordinary work. Deliberately NOT matched: writing only NEW snapshots (`--update=new`, `--update-snapshots=missing`, `--snapshot-update-new-only`, `INSTA_UPDATE=new`), `cargo insta review`, and Jest's `--ci`. Misses a runner started through any other script name or wrapper, and snapshot files rewritten with a file tool. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          `(?:^|[\\s;&|(/])(?:jest|vitest)${ARGS}${UPDATE}`,
          `(?:^|[\\s;&|(/])(?:bun|playwright)\\s+test${ARGS}${UPDATE}`,
          `(?:^|[\\s;&|(])(?:npm|pnpm|yarn|bun)\\s+(?:run\\s+)?test[\\w:-]*${ARGS}${UPDATE}`,
          "\\s--snapshot-update(?![\\w-])",
          "(?:^|[\\s;&|(])cargo\\s+insta\\s+(?:accept|approve)\\b",
          `(?:^|[\\s;&|(])cargo\\s+insta\\s+test${ARGS}--(?:accept|force-update-snapshots)(?![\\w-])`,
          "\\bINSTA_(?:UPDATE\\s*=\\s*[\"']?(?:always|1|force)\\b|FORCE_PASS\\s*=|FORCE_UPDATE_SNAPSHOTS\\s*=)",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("npx jest -u"),
      bash("jest --updateSnapshot src/parser"),
      bash("vitest run -u"),
      bash("pnpm vitest --update"),
      bash("npm test -- -u"),
      bash("pnpm test:unit --update-snapshot"),
      bash("npx playwright test --update-snapshots"),
      bash("bun test --update-snapshots"),
      bash("pytest --snapshot-update tests/"),
      bash("cargo insta accept"),
      bash("cargo insta test --accept"),
      bash("INSTA_UPDATE=always cargo test"),
      pwsh("npx vitest run -u"),
    ],
    allow: [
      ...mentions("vitest run -u"),
      bash("vitest run"),
      bash("npx jest --ci"),
      bash("vitest run --update=new"),
      bash("npx playwright test --update-snapshots=missing"),
      bash("pytest --snapshot-update-new-only"),
      bash("cargo insta review"),
      bash("cargo insta test --check"),
      bash("INSTA_UPDATE=no cargo test"),
      bash("pnpm update vitest"),
      bash("npm install -D jest"),
      bash("git push -u origin feature/x"),
      bash("pip install -U pytest"),
    ],
  },
};
