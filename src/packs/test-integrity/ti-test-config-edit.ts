// cspell:words codecov coveragerc mocharc nycrc phpunit pyproject pytest
import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * A test runner's or coverage tool's own configuration.
 *
 * Only files whose whole purpose is test configuration are matched. `pyproject.toml`, `setup.cfg`,
 * `package.json` and `vite.config.*` can hold test settings too, but matching them by name would
 * ask about every dependency bump and build change.
 */
export const tiTestConfigEdit: Rule = {
  id: "ti.test-config-edit",
  category: "test-integrity",
  severity: "medium",
  defaultAction: "require_approval",
  title: "Editing a test runner or coverage configuration",
  description:
    "Holds a file tool opening a test runner's or coverage tool's own configuration: Jest's `jest.config.*`, Vitest's `vitest.config.*` and legacy `vitest.workspace.*`, `pytest.ini`, `pytest.toml` and their dotted forms, `tox.ini`, Mocha's `.mocharc.*`, PHPUnit's `phpunit.xml`, `phpunit.xml.dist` and `phpunit.dist.xml`, `codecov.yml`, nyc's `.nycrc*` and `nyc.config.*`, `.c8rc`, coverage.py's `.coveragerc`, `karma.conf.*`, and the Playwright and Cypress configs. One line in any of these can exclude a failing file, lower a coverage threshold or retry a flaky test until it passes. File tools carry a path and no content, so it cannot tell a harmless edit from a weakening one, and it does not tell reading apart from editing. Deliberately NOT matched: general files that can also hold test settings — `pyproject.toml`, `setup.cfg`, `package.json`, `vite.config.*` — and test files themselves, since editing a test is how a test gets fixed. Misses test settings kept in those general files, and a config at a path passed with `--config`.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/jest.config.{js,ts,mjs,mts,cjs,cts,json}" },
      {
        kind: "execute_tool",
        file_glob: "**/vitest.{config,workspace}.{js,ts,mjs,mts,cjs,cts,json}",
      },
      {
        kind: "execute_tool",
        file_glob: "**/{pytest.ini,.pytest.ini,pytest.toml,.pytest.toml,tox.ini}",
      },
      { kind: "execute_tool", file_glob: "**/.mocharc.{js,cjs,mjs,yaml,yml,json,jsonc}" },
      { kind: "execute_tool", file_glob: "**/{phpunit.xml,phpunit.xml.dist,phpunit.dist.xml}" },
      { kind: "execute_tool", file_glob: "**/{codecov.yml,.codecov.yml}" },
      {
        kind: "execute_tool",
        file_glob:
          "**/{.nycrc,.nycrc.json,.nycrc.yaml,.nycrc.yml,nyc.config.js,nyc.config.cjs,nyc.config.mjs}",
      },
      { kind: "execute_tool", file_glob: "**/{.c8rc,.c8rc.json,.coveragerc,.coveragerc.toml}" },
      { kind: "execute_tool", file_glob: "**/karma.conf.{js,ts,coffee}" },
      {
        kind: "execute_tool",
        file_glob: "**/{playwright,cypress}.config.{js,ts,mjs,mts,cjs,cts}",
      },
    ],
  },
  fixtures: {
    block: [
      file("vitest.config.ts"),
      file("apps/web/vitest.config.mts", "Write"),
      file("vitest.workspace.ts"),
      file("jest.config.js"),
      file("packages/api/jest.config.cjs", "Write"),
      file("pytest.ini"),
      file("tox.ini"),
      file(".mocharc.yml"),
      file("phpunit.xml.dist"),
      file(".github/codecov.yml"),
      file(".nycrc.json"),
      file(".c8rc.json"),
      file(".coveragerc"),
      file("karma.conf.js"),
      file("playwright.config.ts"),
      file("cypress.config.ts"),
    ],
    allow: [
      file("pyproject.toml"),
      file("setup.cfg"),
      file("package.json"),
      file("vite.config.ts"),
      file("tsconfig.json"),
      file("src/parser.test.ts"),
      file("vitest.setup.ts"),
      file("jest.setup.js"),
      file(".env.test"),
      file("docs/testing.md"),
      file("biome.json"),
    ],
  },
};
