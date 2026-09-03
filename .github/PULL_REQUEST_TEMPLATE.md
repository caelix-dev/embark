## What

A short description of the change and why it's needed.

## Checklist

- [ ] Commit subjects are lowercase and conventional-commit prefixed
      (`fix(codec): ...`, `docs: ...`), with no attribution trailers — see
      [`CONTRIBUTING.md`](../CONTRIBUTING.md).
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
      and `cargo clippy --workspace --all-targets -- -D warnings` pass
- [ ] `cargo test --workspace --all-features` passes
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if this is a
      user-visible change
- [ ] Docs (`README.md`, doc comments) updated if behavior or the public
      API changed

## Notes for reviewers

Anything that needs extra attention: tricky trade-offs, alternatives you
considered, follow-up work you're deliberately leaving out.
