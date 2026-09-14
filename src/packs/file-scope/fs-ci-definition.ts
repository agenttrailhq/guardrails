import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The CI definition is where the checks that gate every merge are written down.
 * An agent that edits it can remove the test job, or add a step that runs with
 * the repository's secrets — and both look like an ordinary diff.
 */
export const fsCiDefinition: Rule = {
  id: "fs.ci-definition",
  category: "file-scope",
  severity: "medium",
  defaultAction: "require_approval",
  title: "Editing the CI pipeline definition",
  description:
    "Holds a file tool opening a CI definition — GitHub Actions workflows and composite actions, .gitlab-ci.yml, a Jenkinsfile, CircleCI, Azure Pipelines, Buildkite or Bitbucket pipelines. This is where the checks that gate every merge are written down, and where a new step would run with the repository's secrets; both edits look like an ordinary diff. Does NOT match other files under .github/ (CODEOWNERS, issue templates), which gate nothing. It MISSES a CI system whose definition lives outside the repository.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/.github/workflows/**" },
      { kind: "execute_tool", file_glob: "**/.github/actions/**" },
      { kind: "execute_tool", file_glob: "**/.gitlab-ci.yml" },
      { kind: "execute_tool", file_glob: "**/Jenkinsfile" },
      { kind: "execute_tool", file_glob: "**/.circleci/config.yml" },
      { kind: "execute_tool", file_glob: "**/azure-pipelines.yml" },
      { kind: "execute_tool", file_glob: "**/.buildkite/**" },
      { kind: "execute_tool", file_glob: "**/bitbucket-pipelines.yml" },
    ],
  },
  fixtures: {
    block: [
      file(".github/workflows/ci.yml"),
      file(".github/actions/setup/action.yml"),
      file(".gitlab-ci.yml"),
      file("Jenkinsfile"),
    ],
    allow: [
      file(".github/CODEOWNERS"),
      file(".github/PULL_REQUEST_TEMPLATE.md"),
      file("package.json"),
      file("README.md"),
    ],
  },
};
