// cspell:words untaint

import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The state file is the only record of what Terraform believes exists. Editing it
 * by hand does not change any infrastructure — it changes what the next apply
 * thinks it has to create or destroy, which is how a `state rm` becomes a deleted
 * production database two commands later.
 */
export const piTerraformStateMutate: Rule = {
  id: "pi.terraform-state-mutate",
  category: "prod-infra",
  severity: "high",
  defaultAction: "require_approval",
  title: "Hand-editing Terraform state",
  description:
    'Mutates the Terraform state file directly — `state rm`, `state mv`, `state push`, `taint`, `untaint`, `force-unlock`. None of these changes any infrastructure by itself; they change what the NEXT apply believes exists, which is how a `state rm` turns into a destroyed resource two commands later. The read-only commands are deliberately NOT matched (`state list`, `state show`, `state pull`, `show`). It cannot see which backend or workspace is selected. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\b(terraform|tofu)\\s+state\\s+(rm|mv|push|replace-provider)\\b",
          "\\b(terraform|tofu)\\s+(taint|untaint)\\b",
          "\\b(terraform|tofu)\\s+force-unlock\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("terraform state rm aws_db_instance.main"),
      bash("terraform state mv aws_s3_bucket.a aws_s3_bucket.b"),
      bash("terraform taint aws_instance.web"),
      bash("terraform force-unlock 1234abcd"),
    ],
    allow: [
      ...mentions("terraform state rm aws_db_instance.main"),
      bash("terraform state list"),
      bash("terraform state show aws_s3_bucket.assets"),
      bash("terraform state pull > state.json"),
      bash("terraform show -json"),
    ],
  },
};
