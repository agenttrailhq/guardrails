// cspell:words kubeconfig

import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The one signal the guard genuinely has about environment: the command said so
 * itself. A read against production is not dangerous, so only the mutating verbs
 * are listed — `kubectl get pods -n production` stays quiet, and that is
 * deliberate rather than an oversight.
 */
export const piProdNamespace: Rule = {
  id: "pi.prod-namespace",
  category: "prod-infra",
  severity: "high",
  defaultAction: "require_approval",
  title: "A mutating kubectl command that names production",
  description:
    'A kubectl command that both MUTATES (delete, apply, scale, patch, replace, rollout, drain, exec, edit, set) and names a production namespace or context in its own text. Reads are deliberately NOT matched — `kubectl get pods -n production` and `kubectl logs -n production` are how you find out what is wrong. This is the only environment signal the guard has: no kubeconfig or current-context reaches it, so a mutating command against production that does not SAY production is invisible to this rule. The mutating verb and the production namespace or context may now appear in either order and after a global flag (`kubectl -n prod delete …`, `kubectl --context=prod-cluster apply …`), and an absolute tool path still matches; as a consequence a config write that names production (`kubectl config set-context … --namespace prod`) is also held, which is acceptable for a prompt rather than a block. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\bkubectl\\b(?=[^|;&]*\\b(?:delete|apply|scale|patch|replace|rollout|drain|exec|edit|set)\\b)[^|;&]*(?:-n|--namespace)[= ]\\s*prod",
          "\\bkubectl\\b(?=[^|;&]*\\b(?:delete|apply|scale|patch|replace|rollout|drain|exec|edit|set)\\b)[^|;&]*--context[= ]\\s*[\\w.-]*prod",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("kubectl delete pod api-7d9 -n production"),
      bash("kubectl apply -f k8s/ --namespace prod"),
      bash("kubectl rollout restart deploy/api --context=prod-eu-west-1"),
      bash("kubectl -n prod delete pod api-7d9"),
      bash("kubectl --context prod-eu apply -f k8s/"),
    ],
    allow: [
      ...mentions("kubectl delete pod api-7d9 -n production"),
      bash("kubectl get pods -n production"),
      bash("kubectl logs -n production deploy/api"),
      bash("kubectl apply -f k8s/ -n staging"),
      bash("kubectl config get-contexts"),
    ],
  },
};
