# Changelog

All notable changes to `@agenttrail/guardrails` are recorded here, in the
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.

The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the
version is below `1.0.0`, a **breaking change bumps the minor** and anything else the patch.
For this package, breaking means a removed guardrail, a renamed guardrail id, or a default
action made stricter; adding a guardrail or a pack is a feature.

## [Unreleased]

## [0.2.0] - 2026-09-18

### Added

- The catalog grew from 56 guardrails across 8 packs to **74 across 11 packs**, adding the
  `agent-context`, `test-integrity` and `exfiltration` packs.

### Fixed

- A leading global flag no longer bypasses the command-channel guardrails — `git -C <path>
  reset --hard`, `npm --silent install <pkg>` and similar are matched again.
- The quoted-mention exemption now holds on compound commands: a command that only *names* a
  dangerous string (in a comment, an `echo`, or a search) is no longer treated as running it.
- `block-curl-pipe-to-shell` now blocks, matching its id, instead of only warning.
- `ssh-keygen -R <host>` (removing a stale host key) is no longer flagged — a false positive
  in the exfiltration patterns.
- `ac.recursive-agent-invoke`'s description now matches what its pattern actually catches.

### Changed

- Raised the `detail_matches` pattern-length cap from 200 to 320 characters.

## [0.1.0] - 2026-09-15

### Added

- First stable catalog: 56 guardrails across 8 packs, the self-contained schema and
  fixtures, and the CI corpus harness that pins the rule count and shape.

## [0.0.2] - 2026-09-14

### Changed

- Pre-release catalog iteration.

## [0.0.1] - 2026-09-11

### Added

- Initial publish.
