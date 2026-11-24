// cspell:words xcopy robocopy mklink execdir rmsync ditto pushd inplace utput webrequest restmethod clau ings worktrees extglob

import { CURLY, GIT_PRE, QUOTED_MENTION, SEP, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, file, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** The folders that hold an agent's hooks, settings and the guard's own state. */
const DIRS = "\\.(?:claude|cursor|codex|agenttrail)";

/**
 * A protected path, written with any root (`~`, `$HOME`, `/Users/<name>`, `C:\Users\<name>`):
 * Claude Code, Cursor or Codex settings, hooks, plugins or config, anything under
 * `.agenttrail/`, or managed settings. The file name starts a path segment, so
 * `.claude/commands/update-settings.md` is not one, and `..` segments still reach it.
 */
const PROT =
  "(?:\\.(?:claude|cursor|codex)[/\\\\](?:[^\\s;&|<>]{0,200}?[/\\\\])?(?:settings(?:\\.local)?\\.json|hooks(?:\\.json|[/\\\\]|[\"']?(?:\\s|$|[;&|)]))|plugins[/\\\\]|config\\.toml)|\\.agenttrail[/\\\\]|managed-settings\\.json)";

/**
 * A character the shell expands or removes inside a name: a glob, a brace or a backtick, or a quote
 * that more of the name follows (`sett"ings`, `".claude"/`). A quote that only closes an argument
 * (`".claude/commands/review.md" /tmp/x`) is not one, nor is a backslash, which PowerShell reads as
 * a separator. The curly quotes count, because PowerShell reads them as quotes.
 */
const X = `(?:[*?\\[{\`]|["'${CURLY}](?=[^\\s;&|<>)"'${CURLY}]))`;

/**
 * A path the shell expands before the command sees it, so that it can name a protected file:
 * - a home dot-folder whose name holds one ({@link X}): `~/.cl*`, `~/.{claude,x}`, `~/".claude"`;
 * - a protected folder, or a path under one, that holds one: `.claude/sett*.json`, `".claude"/x`;
 * - a quoted spelling of the folder name itself: `.cl""aude/`.
 * A file whose name ends in `.md` is never one of these files (`.claude/commands/*.md`), so it is
 * left alone.
 */
const NOT_MD = `(?![^\\s;&|<>{},/\\\\]{0,200}\\.md(?=["'\\s;&|<>)]|$))`;

/** After a folder name, the path it starts does not end in `.md` (`.claude/commands/x.md`). */
const NOT_PROMPT = `(?![^\\s'"\`{},()+\\[\\]]{0,200}\\.md(?=["'\\s\`)]|$))`;
const OBF = [
  `(?:~|\\$\\{?home\\}?|\\$env:userprofile|%userprofile%)[/\\\\]["'\\\\]{0,4}\\.[^\\s/\\\\;&|<>]{0,40}?${X}${NOT_MD}`,
  `${DIRS}(?:[/\\\\][^\\s;&|<>]{0,200}?)?${X}${NOT_MD}`,
  `[^\\w.]\\.[ac][a-z]{0,10}["']{1,4}[a-z]${NOT_MD}`,
];

/**
 * The agent editing its own permissions.
 *
 * This is the pack's sharpest case: a hook config, an MCP server list or a
 * settings file is where "what is this agent allowed to do" is written down, and
 * an agent that can edit it can widen its own reach without anyone reviewing the
 * change. It includes the guard's OWN config, deliberately. File tools are matched by
 * path; a shell command is matched when it writes, moves or deletes one of the same files.
 */
export const fsAgentSelfConfig: Rule = {
  id: "fs.agent-self-config",
  category: "file-scope",
  severity: "high",
  defaultAction: "require_approval",
  owasp: ["ASI02", "LLM03"],
  title: "The agent editing its own configuration",
  description:
    'Holds a file tool opening the files that define what the agent itself is allowed to do — Claude Code settings, hooks and plugins, an MCP server list, a plugin manifest, Cursor rules and hooks, a Codex config and hooks, managed settings, and anything under `.agenttrail/`, which holds the guard\'s own config and guardrails and the platform CLI\'s settings. An agent that can edit these can widen its own reach with nobody reviewing the change. Reading is excluded — the `Read` and `Grep` tools never match — so opening one of these files to read it is not held; every other file tool is, including one this corpus does not know. A shell command that writes, moves or deletes the same files is held too: a redirect (`>`, `>>`, `>|`, `&>`), `tee`, `sponge`, `dd of=`, `sed -i`, `perl -i`, `mv`, `rm`, `ln`, `truncate`, `chmod`, a `cp` or `install` onto the file or into the bare folder (also `-t`), `find … -exec` a write tool or `-delete`, `xargs` into a write tool, a write after `cd` into the folder, a git `checkout` or `restore` of the file, an interpreter one-liner that names the folder and writes, PowerShell `Set-Content`, `Out-File`, `Remove-Item` and their aliases, .NET `[IO.File]::WriteAllText`, and cmd `copy`, `move`, `del`. A path the shell expands (a glob, a brace, or a quote inside the folder or file name, such as `~/.cl*`, `".claude"/settings.json` or `.cl""aude/`) into one of these folders is held when it is written; a quote that only wraps an argument (`cp ".claude/commands/review.md" /tmp/x`, `--exclude=\'.claude/worktrees\'`) is not, and no arm matches a `.md` file under these folders. Reads stay allowed: `cat`, `jq`, `grep`, `git diff`, a `cp` from the file, and a one-liner that only loads it. Does NOT match ordinary project files, or `.claude/commands/*.md`, which are prompts rather than permissions. Bounded to WELL-KNOWN paths: no working directory or project root reaches the guard, so it can only match names it already knows. Also held: `sed --in-place`, a `curl -o`, `wget -O` or PowerShell `Invoke-WebRequest -OutFile` (`iwr`, `irm`) download onto a protected file (which also holds an upload of one, unless the request carries a quoted argument; `ex.file-upload` still holds that), and moving, linking, deleting or `chmod`ing a whole protected folder (`mv ~/.claude ~/.claude.off`), which removes every hook in it. Known over-matches: a quoted protected path as a copy\'s source (`cp "$HOME/.claude/settings.json" /tmp/b.json`), and a name that only starts like a protected file (`rm -f ~/.claude/settings.json.bak`). Known misses: a folder held in a variable (`D=~/.claude; … $D/settings.json`), a write through a link made earlier, a write by a script file, an encoded command, unpacking, syncing or copying a folder into the folder (`tar -C`, `unzip -d`, `rsync dir/ ~/.claude/`, `cp -r dir/ ~/.claude`, `cp -rT`, `Copy-Item -Recurse`, `scp`), a download into the folder by name (`curl --output-dir`, `wget -P`), `rmdir` of an empty folder, the PowerShell alias `mi`, a PowerShell download through splatting (`iwr @p`), `Start-BitsTransfer` or `WebClient.DownloadFile`, `awk -i inplace`, a backslash inside a folder or file name (`.cl\\aude`, `sett\\ings.json`), a quote right after the dot of a relative folder (`."claude"/`), a glob in a relative folder name (`.clau[d]e/`), extended globs (`@(…)`, `+(…)`, `?(…)`, which need the bash option `extglob`), and `~/.claude.json`. A `curl -o` or `wget -O` download is held with or without quoted arguments (`-H "A: b"`, `-d "x"`), also when the shell removes quotes from the flag (`"-o"`, `--"output"`): a write flag on the request ends the mention exemption below. `-o /dev/null` is not a write, so a status check with a quoted body stays a mention. The strong protection is deploying the hooks through managed settings. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone.',
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/.claude/settings*.json" },
      { kind: "execute_tool", file_glob: "**/.claude/hooks/**" },
      { kind: "execute_tool", file_glob: "**/.claude/plugins/**" },
      { kind: "execute_tool", file_glob: "**/.claude-plugin/**" },
      { kind: "execute_tool", file_glob: "**/.mcp.json" },
      { kind: "execute_tool", file_glob: "**/.cursor/rules/**" },
      { kind: "execute_tool", file_glob: "**/.cursor/hooks.json" },
      { kind: "execute_tool", file_glob: "**/.codex/config.toml" },
      { kind: "execute_tool", file_glob: "**/.codex/hooks.json" },
      { kind: "execute_tool", file_glob: "**/.agenttrail/guard/config.json" },
      { kind: "execute_tool", file_glob: "**/.agenttrail/guard/guardrails.json" },
      { kind: "execute_tool", file_glob: "**/.agenttrail/**" },
      { kind: "execute_tool", file_glob: "**/managed-settings.json" },
      // A shell write to a protected path.
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `(?:&?>{1,2}|>\\|)${SEP}{0,4}[^;&|<>\\n]{0,200}${PROT}`,
          `(?:^|[^\\w.-])(?:tee|sponge)\\b[^|;&\\n]{0,200}${PROT}`,
          `\\bdd\\b[^|;&\\n]{0,200}of=[^\\s;&|<>]{0,200}${PROT}`,
          `(?:^|[^\\w.-])(?:sed|perl|ruby)\\b[^|;&\\n]{0,200}${SEP}(?:-[a-z]{0,4}i|--in-place)[^|;&\\n]{0,300}${PROT}`,
          `(?:^|[^\\w.-])(?:mv|rm|unlink|ln|truncate|chmod|chown|shred|del|erase|move|ren|rename|mklink)\\b[^|;&\\n]{0,300}${PROT}`,
          // A copy onto the file: the protected path is the last argument.
          `(?:^|[^\\w.-])(?:cp|install|rsync|ditto|copy|xcopy|robocopy)\\b[^|;&\\n]{0,300}\\s["']?\\S{0,99}${PROT}\\S{0,99}\\s{0,4}(?:$|[;&|)])`,
          // A copy of a settings or hooks file into the bare folder, and -t into it.
          `(?:^|[^\\w.-])(?:cp|mv|install|rsync|ditto|copy|xcopy|move)\\b[^|;&\\n]{0,300}(?:settings|hooks|\\.json|\\.toml)[^|;&\\n]{0,300}\\s["']?[^\\s;&|<>]{0,200}${DIRS}(?:[/\\\\](?:hooks|plugins))?[/\\\\]?["']?\\s{0,4}(?:$|[;&|)])`,
          `(?:^|[^\\w.-])(?:cp|mv|install|ln)\\b[^|;&\\n]{0,200}(?:-t|--target-directory)(?:=|${SEP}{1,4})["']?[^\\s;&|<>]{0,200}${DIRS}\\b`,
          `${GIT_PRE}${SEP}(?:checkout|restore)\\b[^|;&\\n]{0,300}${PROT}`,
          `\\bfind\\b[^|;&\\n]{0,200}${DIRS}\\b(?![/\\\\]commands\\b(?![^\\s;&|]*\\.\\.))[^|;&\\n]{0,300}(?:-delete\\b|-(?:exec|execdir|ok)${SEP}{1,4}["']?(?:sed|perl|rm|mv|cp|tee|truncate|chmod|ln|sh|bash|sponge)\\b)`,
        ],
      },
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `${DIRS}\\b${NOT_PROMPT}[^;&\\n]{0,300}\\|${SEP}{0,4}xargs\\b[^|;&\\n]{0,100}\\b(?:sed|perl|rm|mv|cp|tee|truncate|chmod|ln)\\b`,
          // A write after cd into the folder.
          `\\b(?:cd|pushd|set-location|sl|chdir)${SEP}{1,4}["']?[^\\s;&|]{0,200}\\.agenttrail[^\\s;&|]{0,100}${SEP}{0,4}(?:&&|;|\\|\\||\\n)[^\\n]{0,400}?(?:>|\\b(?:tee|sponge|sed|perl|mv|rm|cp|truncate|ln|set-content|out-file)\\b)`,
          // An interpreter one-liner that names the folder and writes, in either order.
          `\\b(?:python[\\d.]{0,4}|node|ruby|perl|deno|bun)\\s[^\\n]{0,400}(?:${DIRS}\\b${NOT_PROMPT}|managed-settings)[^\\n]{0,300}(?:["'],\\s*["'][wa]|write|unlink|rename|remove|rmsync|truncate|replace)`,
          `\\b(?:python[\\d.]{0,4}|node|ruby|perl|deno|bun)\\s[^\\n]{0,400}(?:write|unlink|rename|remove|rmsync|truncate)[^\\n]{0,300}(?:${DIRS}\\b${NOT_PROMPT}|managed-settings)`,
          // PowerShell cmdlets and their aliases, and .NET file methods.
          `\\b(?:set-content|add-content|out-file|clear-content|new-item|sc|ac|ni)\\b[^|;&\\n]{0,300}${PROT}`,
          `\\b(?:remove-item|move-item|rename-item|copy-item|ri|mi|rni|del|erase)\\b[^|;&\\n]{0,300}${PROT}`,
          `\\]::(?:(?:write|append)all(?:text|lines|bytes)|delete|move|copy|replace)\\b[^\\n]{0,300}${DIRS}\\b${NOT_PROMPT}`,
          // A download onto a protected file (it also holds an upload of one), PowerShell's too.
          // Not read: PowerShell splatting (`iwr @p`), Start-BitsTransfer and WebClient.DownloadFile.
          `\\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\\b[^|;&\\n]{0,300}${PROT}`,
          // The whole folder moved, linked, deleted or locked away.
          `(?:^|[^\\w.-])(?:mv|rm|unlink|ln|chmod|chown|del|erase|move|ren|rename|mklink)\\b[^|;&\\n]{0,300}[\\s/\\\\"']${DIRS}[/\\\\]?["']?(?=\\s|$|[;&|)])`,
        ],
      },
      // A write after cd into a Claude Code, Cursor or Codex folder, to a file a protected name starts.
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: ["(?:cd|pushd|chdir)", "(?:set-location|sl)"].map(
          (cd) =>
            `\\b${cd}${SEP}{1,4}["']?[^\\s;&|]{0,200}\\.(?:claude|cursor|codex)[^\\s;&|]{0,99}${SEP}{0,4}(?:&&|;|\\|\\||\\n)[^\\n]{0,400}?(?:>|\\b(?:tee|sponge|sed|perl|mv|rm|cp|truncate|ln|set-content|out-file)\\b)[^\\n]{0,200}?(?:settings|hooks|plugins|config\\.toml)(?![^\\s{},;&|<>]*\\.md)`,
        ),
      },
      // A write to a path the shell expands into a protected folder.
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `(?:&?>{1,2}|\\b(?:tee|sponge|mv|rm|cp|ln|truncate)\\b)[^;&|<>\\n]{0,300}`,
          `\\b(?:install|rsync|set-content|out-file|copy-item|move-item|remove-item)\\b[^;&|<>\\n]{0,300}`,
          `\\b(?:sed|perl)\\b[^|;&\\n]{0,99}\\s(?:-[a-z]{0,4}i|--in-place)[^;&|<>\\n]{0,300}`,
        ].flatMap((write) => OBF.map((path) => write + path)),
      },
    ],
    none_of: [
      // A read is not an edit. Named as a deny-list rather than an `any_of` over
      // the write tools, so an unknown file tool on a matched path still holds.
      { kind: "execute_tool", label: "{Read,Grep}" },
      ...QUOTED_MENTION,
    ],
  },
  fixtures: {
    block: [
      file(".claude/settings.json"),
      file(".claude/settings.local.json"),
      file("/home/dev/.agenttrail/guard/config.json", "Write"),
      file(".mcp.json"),
      file("/home/dev/.claude/plugins/cache/agenttrail/hooks/hooks.json", "Write"),
      file(".cursor/hooks.json"),
      file("/home/dev/.codex/hooks.json", "Write"),
      file("/home/dev/.agenttrail/os/enforced-projects.json", "Write"),
      file("/home/dev/.agenttrail/pep-fail-mode.json", "Write"),
      file("/Library/Application Support/ClaudeCode/managed-settings.json", "Write"),
      bash("sed -i '' 's/block/warn/' ~/.agenttrail/guard/config.json"),
      bash("echo '{}' > ~/.agenttrail/guard/config.json"),
      bash('echo \'{"mode":"open"}\' > ~/.agenttrail/pep-fail-mode.json'),
      bash("jq . x | sponge ~/.claude/settings.json"),
      bash('jq . x > "$HOME/.claude/settings.json"'),
      bash("echo x >> .claude/settings.local.json"),
      bash("echo x | tee -a ~/.claude/settings.json"),
      bash("grep -v PreToolUse ~/.claude/settings.json | sponge ~/.claude/settings.json"),
      bash("cp /dev/null .cursor/hooks.json"),
      bash("cp x.json ~/.codex/hooks.json"),
      bash("mv ~/.claude/settings.json ~/.claude/settings.bak"),
      bash("rm -rf ~/.claude/plugins/cache/agenttrail"),
      bash("rm -rf ~/.claude/hooks"),
      bash("truncate -s0 ~/.claude/plugins/cache/agenttrail/hooks/hooks.json"),
      bash("ln -sf /dev/null ~/.claude/settings.json"),
      bash("git checkout HEAD~3 -- .claude/settings.json"),
      bash("git restore .claude/settings.json"),
      bash("cp settings.json ~/.claude/"),
      bash("mv hooks.json ~/.cursor"),
      bash("cp -t ~/.claude settings.json"),
      bash("find ~/.claude -name settings.json -exec sed -i s/a/b/ {} +"),
      bash("find ~/.claude/plugins -delete"),
      bash("ls ~/.claude/*.json | xargs sed -i s/a/b/"),
      bash("cd ~/.claude && sed -i s/a/b/ settings.json"),
      bash("cd ~/.agenttrail && rm -rf guard"),
      // The long form of -i, a download onto the file, and the whole folder moved or linked away.
      bash("sed --in-place s/a/b/ ~/.claude/settings.json"),
      bash("curl -o ~/.claude/settings.json https://example.com/s"),
      bash("wget -O ~/.claude/settings.json https://example.com/s"),
      // A quoted argument does not make a download a mention: the write flag ends the exemption.
      bash('curl -H "A: b" -o ~/.agenttrail/guard/config.json https://example.com/c'),
      bash('wget --post-data "x" -O ~/.claude/settings.json https://example.com/s'),
      bash('curl -d "x" https://example.com/s -o ~/.claude/settings.json'),
      bash('curl -sSL -H "A: b" -o~/.claude/settings.json https://example.com/s'),
      bash('curl -H "A: b" --output=$HOME/.claude/settings.json https://example.com/s'),
      bash('curl -H "A: b" --output-dir ~/.agenttrail/guard -O https://example.com/config.json'),
      bash('wget --header "A: b" --output-document ~/.claude/settings.json https://example.com/s'),
      bash('wget -q --header "A: b" -O~/.codex/config.toml https://example.com/c'),
      // Quotes the shell removes from the flag, a cluster with #, and /dev/null beside a real -o.
      bash('curl "-o" ~/.claude/settings.json -d "x" https://example.com/s'),
      bash("curl '-o' ~/.claude/settings.json -H \"A: b\" https://example.com/s"),
      bash('curl -"o" ~/.claude/settings.json -d "x" https://example.com/s'),
      bash("curl -'o' ~/.claude/settings.json -H \"A: b\" https://example.com/s"),
      bash('curl --"output" ~/.claude/settings.json -d "x" https://example.com/s'),
      bash('curl --o""utput ~/.claude/settings.json -d "x" https://example.com/s'),
      bash('curl -#o ~/.claude/settings.json -H "A: b" https://example.com/s'),
      bash('curl -s -o /dev/null -o ~/.claude/settings.json -d "x" https://example.com/s'),
      pwsh(
        'Invoke-WebRequest -Uri https://example.com/s -OutFile $HOME\\.claude\\settings.json -Body "x"',
      ),
      pwsh("iwr https://example.com/s -OutFile $HOME\\.claude\\settings.json"),
      bash("mv ~/.claude ~/.claude.off"),
      bash("mv .claude .claude-off"),
      bash("mv ~/.agenttrail ~/.x"),
      bash('mv "$HOME/.cursor/" /tmp/c'),
      bash("chmod 000 ~/.claude"),
      bash("ln -s ~/.claude c && echo x > c/settings.json"),
      bash("python3 -c \"open('/Users/x/.claude/settings.json','w').write('{}')\""),
      bash("node -e \"fs.writeFileSync(path.join(os.homedir(),'.claude','settings.json'),'{}')\""),
      bash("python3 -c \"(Path.home()/'.claude'/'settings.json').write_text('{}')\""),
      bash("echo x > ~/.claude/../.claude/settings.json"),
      bash("echo x > ~/.cursor/rules/../hooks.json"),
      bash("echo x > '/Library/Application Support/ClaudeCode/managed-settings.json'"),
      bash("copy NUL %USERPROFILE%\\.cursor\\hooks.json"),
      pwsh("Set-Content -Path $HOME\\.claude\\settings.json -Value '{}'"),
      pwsh("[IO.File]::WriteAllText(\"$HOME\\.claude\\settings.json\",'{}')"),
      // A path the shell expands into a protected folder.
      bash("echo x > ~/.cl*/settings.json"),
      bash("cp x ~/.{claude,x}/settings.json"),
      bash("sed -i s/a/b/ ~/.claude/sett*.json"),
      bash('echo x > ~/".claude"/settings.json'),
      bash("tee ~/.claude/setting[s].json < x"),
      pwsh("Set-Content $HOME\\.claude\\\u201csettings.json\u201d '{}'"),
      pwsh("Set-Content $HOME\\.claude\\\u2018settings.json\u2019 '{}'"),
      bash('echo x > ".claude"/settings.json'),
      bash('echo x > .cl""aude/settings.json'),
      bash("echo x > ~/.cla?de/settings.json"),
      bash("echo x > $HOME/.claude/settings.js*"),
      bash('echo x > ".claude/sett"ings.json'),
      // A .md inside a brace list, a .md folder then .., and a .md later in a one-liner.
      bash("echo '{}' | tee ~/.claude/{settings.json,x.md}"),
      bash("sed -i s/a/b/ ~/.claude/{settings.json,x.md}"),
      bash("sed -i s/a/b/ ~/.claude/s*{,.md}"),
      bash("cp x ~/.claude/{settings.json,n.md}"),
      bash("sed -i s/a/b/ ~/.cl*/x.md/../settings.json"),
      bash("ls ~/.claude/{settings.json,x.md} | xargs sed -i s/a/b/"),
      bash("find ~/.claude/commands/.. -name settings.json -exec sed -i s/a/b/ {} +"),
      bash("find ~/.claude/commands/../ -delete"),
      bash(
        "node -e \"require('fs').writeFileSync(os.homedir()+`/.claude/settings.json`,[`{}`,`.md`][0])\"",
      ),
      bash("cd .claude && tee {settings.json,x.md} < y"),
      // A .md in the next command, with no blank before the separator.
      bash("cd .claude && echo {} >settings.json;:>x.md"),
      bash("cd .claude && echo {} >settings.json&&:>x.md"),
      bash("cd .claude && echo {} >settings.json&:>x.md"),
      bash("cd .claude && echo {} >settings.json|:>x.md"),
      bash("cd .claude && tee settings.json<y;:>x.md"),
      pwsh(`[IO.File]::WriteAllText("$HOME\\.claude\\x.md\\..\\settings.json", 'x')`),
    ],
    allow: [
      file(".claude/commands/deploy.md"),
      file("src/index.ts"),
      file("package.json"),
      file("README.md"),
      file(".claude/settings.json", "Read"),
      file(".mcp.json", "Grep"),
      ...mentions("echo x > ~/.claude/settings.json"),
      bash("cat ~/.claude/settings.json"),
      bash("jq .hooks ~/.claude/settings.json"),
      bash("cp ~/.claude/settings.json /tmp/settings-backup.json"),
      bash("grep -n hooks ~/.cursor/hooks.json"),
      bash("git diff .claude/settings.json"),
      bash("echo x > .claude/commands/update-settings.md"),
      bash("echo x > .claude/commands/hooks-guide.md"),
      bash("python3 -c \"import json;print(json.load(open('/Users/x/.claude/settings.json')))\""),
      bash("find ~/.claude -name '*.json' -exec cat {} \\;"),
      bash("cd ~/.claude && ls"),
      bash("ls ~/.agenttrail/"),
      bash("mv build/app.cursor.bak /tmp/x"),
      bash("curl -o out.json https://example.com/s"),
      // A quoted body that only names a write, with no write flag, stays a mention.
      bash('curl -d "echo x > ~/.claude/settings.json" https://api.example.com/notes'),
      bash('wget --post-data "mv ~/.claude ~/.claude.off" https://api.example.com/notes'),
      // A status check writes the response to /dev/null, which is not a write.
      bash(
        'curl -s -o /dev/null -w "%{http_code}" -d "echo x > ~/.claude/settings.json" https://api.example.com/n',
      ),
      bash(
        'curl -H "A: b" -d "sed -i s/a/b/ ~/.claude/settings.json" https://api.example.com/n | grep -o ok',
      ),
      bash("rm -f ~/.claude.json.bak"),
      // A quote that only wraps an argument, an exclude, and the prompt files, on every arm.
      bash(`rsync -a --exclude='.claude/worktrees' "$WT"/ "$SCRATCH"/`),
      bash('rsync -a --exclude=".cursor/rules" ./ ../copy/'),
      bash('cp ".claude/commands/review.md" /tmp/review.md'),
      bash('mv "notes.md" ".claude/commands/notes.md"'),
      bash('echo hi > "docs/.claude/README.md"'),
      bash("cp x .claude/commands/*.md"),
      bash("cd .claude && echo x > commands/hooks-guide.md"),
      bash("python3 -c \"open('.claude/commands/x.md','w').write('a')\""),
      bash("find .claude/commands -name '*.md' -exec sed -i s/a/b/ {} +"),
      bash("ls .claude/commands/*.md | xargs sed -i s/a/b/"),
      bash("cp -r templates/ ~/.config/myapp/"),
      bash("echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> ~/.zshrc"),
    ],
  },
};
