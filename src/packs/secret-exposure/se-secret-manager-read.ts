import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Reading a secret out of a manager and into the shell — where it lands in the
 * terminal buffer, the trace, and quite possibly a log. `warn`, not a hold: this
 * is a normal step in a normal day, and the value of the signal is that someone
 * can see it happened afterwards.
 */
export const seSecretManagerRead: Rule = {
  id: "se.secret-manager-read",
  category: "secret-exposure",
  severity: "medium",
  defaultAction: "warn",
  title: "Reading a secret out of a secrets manager",
  description:
    'Surfaces a secret being read from AWS Secrets Manager or SSM, HashiCorp Vault, Google Secret Manager, Azure Key Vault, a Kubernetes secret dumped as yaml or json, or Doppler. Non-blocking: this is a normal step in a normal day, and the value is that it is visible afterwards. The listing commands are deliberately NOT matched (`list-secrets`, `vault status`, `kubectl get secrets` without an output flag). It does NOT see a secret read by application code, by an SDK, or from an environment variable already in the process. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\baws\\s+secretsmanager\\s+get-secret-value\\b",
          "\\baws\\s+ssm\\s+get-parameters?\\b[^|;&]*--with-decryption\\b",
          "\\bvault\\s+(read|kv\\s+get)\\b",
          "\\bgcloud\\s+secrets\\s+versions\\s+access\\b",
          "\\baz\\s+keyvault\\s+secret\\s+show\\b",
          "\\bkubectl\\s+get\\s+secrets?\\b[^|;&]*-o\\s*(json|yaml)\\b",
          "\\bdoppler\\s+secrets\\s+(get|download)\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("aws secretsmanager get-secret-value --secret-id prod/db"),
      bash("vault kv get secret/app/db"),
      bash("kubectl get secret app-env -o yaml"),
      bash("gcloud secrets versions access latest --secret=db-password"),
    ],
    allow: [
      ...mentions("aws secretsmanager get-secret-value --secret-id prod/db"),
      bash("aws secretsmanager list-secrets"),
      bash("vault status"),
      bash("kubectl get secrets"),
      bash("gcloud secrets list"),
    ],
  },
};
