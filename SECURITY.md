# Security Policy

## How to report

Email **[security@agenttrail.sh](mailto:security@agenttrail.sh)**. Keep vulnerability
details out of GitHub issues, pull requests, and discussions until a fix is released.

A useful report includes the rule id, the package version, the command or path involved, and
what goes wrong, with secrets and private project details removed. Please confirm the problem
still occurs on the [latest npm release](https://www.npmjs.com/package/@agenttrail/guardrails).
We welcome coordinated disclosure and will work with you on timing.

## In scope

- **A shipped rule whose pattern can be made to backtrack.** The guard fails open under a time
  limit, so a slow pattern lets the command through rather than merely running slowly.
- **A problem with the published `@agenttrail/guardrails` package itself.**

Problems in the tool that enforces these rules belong to
[AgentTrail Guard's security policy](https://github.com/agenttrailhq/guard/blob/main/SECURITY.md).

## Out of scope

- **A dangerous command that no rule matches.** That is a rule gap, and the fix benefits from
  public review: open a [Guardrails issue](https://github.com/agenttrailhq/guardrails/issues).
- **The limits the README describes** in
  [What these rules deliberately do not catch](README.md#what-these-rules-deliberately-do-not-catch).
