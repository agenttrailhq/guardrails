// cspell:words kubeconfig

import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mcp, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `kubectl delete` and `kubectl drain` remove running workloads. The guard cannot
 * see which cluster is selected — no kubeconfig, no context, no environment
 * reaches it — so it cannot ask "is this production"; `pi.prod-namespace` covers
 * the case where the command itself says so.
 */
export const piKubectlDelete: Rule = {
  id: "pi.kubectl-delete",
  category: "prod-infra",
  severity: "high",
  defaultAction: "require_approval",
  title: "kubectl delete / drain removes running workloads",
  description:
    'Deletes Kubernetes objects or drains a node, both of which stop running workloads. Held for approval rather than blocked because deleting a test deployment is routine. The guard CANNOT tell which cluster is selected — no kubeconfig, context or environment variable reaches it — so this fires the same way against a kind cluster and against production; pi.prod-namespace covers the case where the command itself names the environment. Does NOT match the read verbs (`get`, `describe`, `logs`) or `kubectl apply`. Global flags between `kubectl` and its verb are tolerated (`kubectl -n <ns> delete …`, `--context <ctx>`, `--kubeconfig <f>`), and an absolute tool path still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\bkubectl${LEADING_FLAGS}\\s+delete\\b`,
          `\\bkubectl${LEADING_FLAGS}\\s+drain\\b`,
          `\\bkubectl${LEADING_FLAGS}\\s+(scale|patch)\\b[^|;&]*--replicas[= ]0\\b`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("kubectl delete deployment api"),
      bash("kubectl delete -f k8s/deployment.yaml"),
      bash("kubectl drain node-3 --ignore-daemonsets"),
      bash("kubectl scale deploy/api --replicas=0"),
      bash("kubectl -n prod delete deployment api"),
      bash("kubectl --context prod-eu drain node-3 --ignore-daemonsets"),
      mcp({ command: "kubectl delete deployment api" }),
    ],
    allow: [
      ...mentions("kubectl delete deployment api"),
      bash("kubectl get pods"),
      bash("kubectl describe pod api-7d9"),
      bash("kubectl logs -f deploy/api"),
      bash("kubectl apply -f k8s/"),
      bash("kubectl scale deploy/api --replicas=3"),
    ],
  },
};
