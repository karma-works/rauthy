# Security finding: check it, and check Copilot's fix

You run unattended in CI inside the rauthy builder container (Rust 1.95.0, Node, `just`; UI and
WASM are built). This is the ArztAgent fork of sebadob/rauthy, our identity provider; read
`AGENTS.md` first. The checkout is the branch `copilot-autofix/alert-<n>`: `main` plus, if
Copilot Autofix produced one, its fix as the last commit (`git show HEAD`, compare with
`git log -1 origin/main`). The alert and the autofix status follow below.

## Decide

1. Is the finding real? Read the code path, its callers and the inputs that reach it. A
   finding in test code, generated code or a path no attacker controls may be a false positive.
2. If it is real, is Copilot's fix correct and complete? It must close the hole on every path,
   keep behaviour and API, keep the fork's hardening (force_mfa, passkeys, recovery codes, PIN
   login), and compile and pass the tests. Autofixes are often partial or change behaviour.

Then pick exactly one decision:

- `accept`: the autofix is right as it is. Change nothing.
- `improve`: the autofix is the right idea but needs edits; make them.
- `own-fix`: the finding is real but the autofix is wrong, missing or too broad; revert it
  (`git revert --no-edit HEAD` only if HEAD is the autofix commit, or edit by hand) and write
  the smallest correct fix yourself.
- `dismiss`: not a vulnerability here. `dismissed_reason` is `false positive`, `won't fix`
  (real but accepted, say why) or `used in tests`.
- `unsure`: you cannot tell with confidence. A human decides.

## Rules

- Do NOT commit, push, or touch `.github/`. Do not upgrade dependencies (Dependabot does that).
- For `accept`, `improve`, `own-fix` run until green: `cargo fmt --check`,
  `cargo clippy --locked -- -D warnings`, `cargo test --locked --lib` for the touched crates;
  frontend changes also `cd frontend && npm run check`. Add a unit test that fails without the
  fix where that is practical.
- This repository is public. The summary goes into a public PR or alert comment: describe the
  fix, not a step-by-step exploit.

## Output

Write `FINDING_VERDICT.json` in the repository root (it is not committed):

    {"decision": "...", "dismissed_reason": "...", "summary": "...", "tests": "..."}

`summary`: German, 3-8 sentences: is the finding real and why; what Copilot proposed and why
you kept, changed or rejected it; what the final change does. `tests`: commands and results.
