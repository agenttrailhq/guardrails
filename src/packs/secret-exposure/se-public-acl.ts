// cspell:words allusers bgsutil gsutil

import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Making a storage bucket world-readable. The near-miss is the same command with
 * `--acl private`, which is why that is the `allow` fixture rather than `ls`.
 */
export const sePublicAcl: Rule = {
  id: "se.public-acl",
  category: "secret-exposure",
  severity: "high",
  defaultAction: "require_approval",
  title: "Making cloud storage publicly readable",
  description:
    'Holds a command that opens object storage to the public — an S3 `--acl public-read`, a GCS binding to allUsers, an Azure container set to blob or container access, or turning off S3 public-access blocking. The private spellings of the same commands are deliberately NOT matched. It reads the command\'s own words, so a bucket made public through a console, a Terraform apply, or a bucket policy JSON file is invisible to it. Global flags between a storage CLI and its subcommand are tolerated (`aws --profile <p> s3api …`, `gcloud --project=<p> storage …`), and an absolute tool path still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\baws${LEADING_FLAGS}\\s+s3(api)?\\b[^|;&]*--acl\\s+public-read`,
          `\\bgsutil${LEADING_FLAGS}\\s+iam\\s+ch\\b[^|;&]*allusers\\b`,
          `\\bgcloud${LEADING_FLAGS}\\s+storage\\s+buckets\\s+add-iam-policy-binding\\b[^|;&]*allusers\\b`,
          `\\baws${LEADING_FLAGS}\\s+s3api\\s+put-public-access-block\\b[^|;&]*false\\b`,
          `\\baz${LEADING_FLAGS}\\s+storage\\s+container\\s+set-permission\\b[^|;&]*--public-access\\s+(blob|container)\\b`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("aws s3 cp dist/ s3://assets/ --recursive --acl public-read"),
      bash("gsutil iam ch allUsers:objectViewer gs://assets"),
      bash(
        "aws s3api put-public-access-block --bucket assets --public-access-block-configuration BlockPublicAcls=false",
      ),
      bash("aws --profile prod s3 cp dist/ s3://assets/ --recursive --acl public-read"),
    ],
    allow: [
      ...mentions("aws s3 cp dist/ s3://assets/ --recursive --acl public-read"),
      bash("aws s3 cp dist/ s3://assets/ --recursive --acl private"),
      bash("gsutil ls gs://assets"),
      bash("aws s3api get-bucket-acl --bucket assets"),
      bash("aws s3 ls s3://assets"),
    ],
  },
};
