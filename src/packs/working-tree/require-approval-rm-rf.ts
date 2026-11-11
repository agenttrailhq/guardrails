import {
  ARG_END,
  QUOTED_MENTION,
  RM_ARGS,
  RM_RECURSIVE,
  RM_WORD,
  SHELL_AND_MCP,
} from "../../exemptions.js";
import { bash, mcp, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** The build and cache directories whose removal is exempt. */
const BUILD_DIR =
  "(?:\\./)?(?:node_modules|dist|build|out|coverage|target|\\.next|\\.turbo|\\.cache|\\.vite|\\.parcel-cache)";

/**
 * The id has no dotted pack prefix. Guardrail ids are stable identifiers, so it is not
 * renamed to match the others.
 *
 * The build-directory exemption covers one `rm` whose every argument is a flag, `--`
 * or a build directory, and which ends the command or its segment. The end may also be
 * a closing quote, brace or backslash, which is where an MCP tool's JSON input or a
 * `bash -c "…"` string ends. A subpath of a build directory is exempt, including a
 * dot-led cache such as `node_modules/.vite`, but a path segment may hold at most one
 * leading dot followed by a word character, so `..` segments that leave the directory
 * are not. A build directory followed by any other target is not exempt.
 */
export const requireApprovalRmRf: Rule = {
  id: "require-approval-rm-rf",
  category: "working-tree",
  severity: "high",
  defaultAction: "require_approval",
  owasp: ["ASI02", "LLM03"],
  title: "Hold `rm -rf` for approval",
  description:
    'Recursive delete: held for approval rather than blocked, which is the right strength for an operation that is destructive but often legitimate. Catches a recursive flag in any argument of the `rm`, with or without force: `-rf`, `-Rf`, `-fr`, `-r -f`, `-r` alone and `--recursive`, before or after the target, and PowerShell\'s `Remove-Item -Recurse`. Clearing a build directory is EXEMPT (node_modules, dist, build, out, coverage, target, .next, .turbo, .cache, .vite, .parcel-cache, and paths inside them) when every target of that `rm` is one: that shape appears about 220 times in real Claude Code traces against about 3 for a dangerous delete, and a check that asks every time is one people switch off. An absolute path, a $VARIABLE, a ~ path, a source directory, a `..` path out of a build directory, or a build directory followed by another target still asks. `git rm -r --cached` alone, which touches only the index, is exempt. Known misses: a delete via a file tool; a build-directory clean-up chained before a second delete in the same command, because the exemption covers the whole command; and an `rm` with more than twelve arguments before the recursive flag. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `${RM_WORD}${RM_ARGS}[ \\t]+${RM_RECURSIVE}${ARG_END}`,
          "\\bremove-item\\b[^|;&]*-recurse",
        ],
      },
    ],
    none_of: [
      ...QUOTED_MENTION,
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `${RM_WORD}(?:[ \\t]+-{1,2}[a-z][a-z-]{0,24}){1,8}(?:[ \\t]+--)?(?:[ \\t]+${BUILD_DIR}(?:/\\.?[\\w-][\\w.-]{0,60}){0,4}/?){1,11}[ \\t]*(?:$|[;&|)"'}\\\\])`,
          // A single `git rm --cached`, with no shell metacharacter, touches only the index.
          "^\\s*git(?:\\s+-\\S{1,40}){0,6}\\s+rm\\s[^;&|<>()`$\"'\\n]{0,250}--cached\\b[^;&|<>()`$\"'\\n]{0,250}$",
        ],
      },
    ],
  },
  fixtures: {
    block: [
      bash("rm -Rf /home/user/projects"),
      bash("rm -fr src/generated"),
      bash("rm -rf $HOME/Projects/old-client"),
      pwsh("Remove-Item -Recurse -Force C:/projects/old"),
      bash("rm -r -f src/generated"),
      bash("rm -r ~/old-client"),
      bash("rm -R $HOME/scratch"),
      bash("rm src/generated -rf"),
      bash("rm -rf node_modules ~/projects"),
      bash("rm -rf node_modules/../.."),
      bash("rm -rf node_modules/.."),
      mcp({ command: "rm -rf node_modules ~/projects" }),
      bash("git rm -r src/legacy"),
      bash("git rm -r --cached vendor && rm -r src"),
    ],
    allow: [
      ...mentions("rm -Rf /home/user/projects"),
      bash("rm -rf ./node_modules"),
      bash("rm -rf node_modules"),
      bash("rm -rf build/"),
      bash("rm -rf dist"),
      bash("./confirm -rf x"),
      bash("rm package-lock.json"),
      bash("rm -r -f node_modules"),
      bash("rm -f -r ./dist"),
      bash("rm -r node_modules dist"),
      bash("rm -rf dist/assets"),
      bash("rm -rf node_modules && pnpm install"),
      bash("git rm -r --cached vendor"),
      bash("docker run --rm -it node:20 npm test"),
      bash("rm -v notes.txt"),
      bash("rm -rf node_modules/.vite"),
      bash('bash -c "rm -r -f node_modules"'),
      mcp({ command: "rm -r -f node_modules" }),
    ],
  },
};
