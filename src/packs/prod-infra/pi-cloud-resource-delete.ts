import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The delete verbs of the three big cloud CLIs. Each vendor spells it slightly
 * differently — `delete-<noun>` for AWS, a trailing `delete` subcommand for
 * gcloud and az — and the list verbs sit right beside them, which is why the
 * `allow` fixtures are `describe`, `list` and `get`.
 */
export const piCloudResourceDelete: Rule = {
  id: "pi.cloud-resource-delete",
  category: "prod-infra",
  severity: "high",
  defaultAction: "require_approval",
  title: "Deleting a cloud resource from a vendor CLI",
  description:
    'Deletes or terminates a cloud resource through the AWS, gcloud or Azure CLI, including emptying an S3 bucket. The read verbs that sit right beside them — describe, list, get — are deliberately NOT matched. This rule reads the command\'s own words, so it cannot tell which account or project is configured, and it MISSES a delete performed through an SDK, a Terraform apply (see pi.terraform-auto-approve), or a vendor CLI other than these three. Global flags between a cloud CLI and its subcommand are tolerated (`aws --profile <p> …`, `aws --region <r> …`, `gcloud --project=<p> …`), and an absolute tool path still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\baws${LEADING_FLAGS}\\s+[a-z0-9-]+\\s+(delete|terminate|remove)-[a-z-]+`,
          `\\baws${LEADING_FLAGS}\\s+s3\\s+rb\\b`,
          `\\baws${LEADING_FLAGS}\\s+s3\\s+rm\\b[^|;&]*--recursive\\b`,
          `\\bgcloud${LEADING_FLAGS}\\s+[a-z0-9 -]{0,40}\\s+delete\\b`,
          `\\baz${LEADING_FLAGS}\\s+[a-z0-9 -]{0,40}\\s+delete\\b`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("aws ec2 terminate-instances --instance-ids i-abc"),
      bash("aws s3 rb s3://prod-assets --force"),
      bash("gcloud compute instances delete web-1"),
      bash("az group delete --name prod-rg"),
      bash("aws --profile prod ec2 terminate-instances --instance-ids i-abc"),
      bash("aws --region us-east-1 s3 rb s3://prod-assets --force"),
      bash("gcloud --project=acme compute instances delete web-1"),
    ],
    allow: [
      ...mentions("aws ec2 terminate-instances --instance-ids i-abc"),
      bash("aws s3 ls"),
      bash("aws ec2 describe-instances"),
      bash("gcloud compute instances list"),
      bash("az group list"),
    ],
  },
};
