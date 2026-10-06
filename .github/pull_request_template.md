<!-- Thanks for contributing! The rule format and checklist are in CONTRIBUTING.md. -->

## What this changes

<!-- The rule you added or changed, the command shape it catches, and why it matters. -->

## Checklist

- [ ] The rule is filed in the pack for the harm it prevents
- [ ] Its `id` is new and final; renaming it later breaks configs that reference it
- [ ] Its `description` says what it catches and what it misses
- [ ] It has at least one `block` and one `allow` fixture, of the right kind
- [ ] Rule counts are updated in `__tests__/corpus.test.ts` and `README.md`, if it adds a rule
- [ ] `pnpm test`, `pnpm lint`, `pnpm spell`, and `pnpm typecheck` pass
- [ ] Commit messages follow Conventional Commits
