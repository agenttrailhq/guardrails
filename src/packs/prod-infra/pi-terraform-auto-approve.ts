import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `-auto-approve` is the flag that removes the human from the one place
 * Terraform deliberately put one. The plan/apply pair is exactly the near-miss
 * that must stay quiet, so both halves of it are `allow` fixtures.
 */
export const piTerraformAutoApprove: Rule = {
  id: "pi.terraform-auto-approve",
  category: "prod-infra",
  severity: "high",
  defaultAction: "require_approval",
  title: "Terraform apply/destroy without the confirmation prompt",
  description:
    'Applies or destroys infrastructure with `-auto-approve`, which removes the interactive confirmation Terraform puts there on purpose. Held for approval rather than blocked, because it is the correct flag inside CI. Does NOT match `terraform plan`, `terraform validate`, `terraform fmt`, or `terraform apply tf.plan` against a saved plan file — a saved plan was already reviewed, which is the whole point of saving it. It cannot tell which workspace or account is selected, because no environment reaches the guard. A global option between the tool and its subcommand is tolerated (`terraform -chdir=<dir> apply -auto-approve`, `--no-color`), and an absolute tool path still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\b(terraform|tofu|terragrunt)${LEADING_FLAGS}\\s+(apply|destroy)\\b[^|;&]*-auto-approve\\b`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("terraform apply -auto-approve"),
      bash("terraform destroy -auto-approve -var-file=prod.tfvars"),
      bash("tofu apply -auto-approve"),
      bash("terraform -chdir=/infra apply -auto-approve"),
    ],
    allow: [
      ...mentions("terraform apply -auto-approve"),
      bash("terraform plan -out tf.plan"),
      bash("terraform apply tf.plan"),
      bash("terraform validate"),
      bash("terraform fmt -recursive"),
    ],
  },
};
