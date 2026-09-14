// cspell:words clusterrole clusterrolebinding clusterrolebindings rolebinding serviceaccount

import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Handing out permissions in a cloud account or a cluster. Nothing breaks at the
 * moment it happens, which is why it wants a person: the consequence is what
 * some other identity can do afterwards.
 */
export const psIamGrant: Rule = {
  id: "ps.iam-grant",
  category: "privilege-supply-chain",
  severity: "high",
  defaultAction: "require_approval",
  title: "Granting permissions to an identity",
  description:
    'Holds a command that attaches a policy, creates an access key, adds an IAM binding or creates a Kubernetes role binding. Nothing breaks at the moment it runs — the consequence is what some other identity can do afterwards, which is exactly why a person should see it. The read verbs are deliberately NOT matched (`iam list-users`, `get-iam-policy`, `get clusterrolebindings`). It cannot judge whether the grant is narrow or wide, only that one is being made. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\baws\\s+iam\\s+(attach|put)-(user|role|group)-policy\\b",
          "\\baws\\s+iam\\s+(create-access-key|add-user-to-group|create-login-profile)\\b",
          "\\bgcloud\\s+[a-z-]+\\s+add-iam-policy-binding\\b",
          "\\bkubectl\\s+create\\s+(cluster)?rolebinding\\b",
          "\\baz\\s+role\\s+assignment\\s+create\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash(
        "aws iam attach-role-policy --role-name app --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
      ),
      bash("aws iam create-access-key --user-name deploy"),
      bash(
        "kubectl create clusterrolebinding ci-admin --clusterrole=cluster-admin --serviceaccount=ci:default",
      ),
      bash("gcloud projects add-iam-policy-binding p --member=user:x@y.z --role=roles/owner"),
    ],
    allow: [
      ...mentions(
        "aws iam attach-role-policy --role-name app --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
      ),
      bash("aws iam list-users"),
      bash("aws iam get-user --user-name deploy"),
      bash("kubectl get clusterrolebindings"),
      bash("gcloud projects get-iam-policy p"),
    ],
  },
};
