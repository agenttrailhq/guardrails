// cspell:words kubeconfig pypirc
import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The file-channel half of this pack: the paths where a credential actually
 * lives on disk. Filed here BY HARM rather than in `file-scope` — what it
 * protects is the secret inside the file, not the fact that a path was touched.
 *
 * `.pub` is excluded because a public key is public; that exclusion is also the
 * reason `**​/.ssh/id_*` is safe to write as a wildcard.
 */
export const seCredentialFile: Rule = {
  id: "se.credential-file",
  category: "secret-exposure",
  severity: "high",
  defaultAction: "require_approval",
  title: "Opening a file that holds credentials",
  description:
    "Holds a file tool opening a path where credentials live — an SSH private key, an AWS credentials file, a PEM/P12/PFX/JKS keystore, `.npmrc` or `.pypirc` (which hold registry tokens), a Docker config, or a kubeconfig. Public keys are excluded (`*.pub`). It matches the PATH ONLY: it cannot tell whether the file actually holds a secret, so a `.pem` that is a public certificate is held too, and a credential in a file named something else is missed entirely. `.env` files are covered separately by block-env-file-read.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/.ssh/id_*" },
      { kind: "execute_tool", file_glob: "**/id_rsa" },
      { kind: "execute_tool", file_glob: "**/id_ed25519" },
      { kind: "execute_tool", file_glob: "**/.aws/credentials" },
      { kind: "execute_tool", file_glob: "**/*.pem" },
      { kind: "execute_tool", file_glob: "**/*.{p12,pfx,jks,keystore}" },
      { kind: "execute_tool", file_glob: "**/.npmrc" },
      { kind: "execute_tool", file_glob: "**/.pypirc" },
      { kind: "execute_tool", file_glob: "**/.docker/config.json" },
      { kind: "execute_tool", file_glob: "**/.kube/config" },
    ],
    none_of: [{ kind: "execute_tool", file_glob: "**/*.pub" }],
  },
  fixtures: {
    block: [
      file("/home/dev/.ssh/id_rsa", "Read"),
      file("/Users/dev/.aws/credentials", "Read"),
      file("certs/server.pem", "Read"),
      file(".npmrc", "Write"),
    ],
    allow: [
      file("/home/dev/.ssh/id_rsa.pub", "Read"),
      file("certs/server.crt", "Read"),
      file("src/index.ts"),
      file("package.json"),
    ],
  },
};
