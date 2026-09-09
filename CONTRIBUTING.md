# Contributing to embark

Thanks for considering a contribution. `embark` is a small Cargo workspace
(`embark`, `embark-codec`, `embark-crypt`, `embark-format`,
`embark-macros`); most changes touch one or two of these crates.

## Before you start

For anything beyond a small fix — a new codec, a new cipher, a public API
change — please open an issue first to discuss the approach. It's much
easier to agree on a design before code exists than to rework a finished
PR.

## Development

The workspace uses stable Rust; MSRV is **1.87** (`edition = "2024"`).

Gate commands (the same ones CI runs — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
```

If your change touches feature flags, it's worth also checking a build
doesn't silently depend on a feature it didn't declare. This is the sweep
CI runs (every single feature and every pair, with the lints on, since a
degenerate combination usually still compiles and only warns):

```sh
cargo hack clippy --workspace --feature-powerset --depth 2 -- -D warnings
```

For `no_std` and cross-codec interop, see the `no_std` and `interop` jobs
in the CI workflow — they're the easiest way to reproduce those locally
too (same commands, just run them yourself).

### Fuzzing

Every decoder reads untrusted bytes, so the decoders, the encoders' round
trips and the glob matcher each have a fuzz target under [`fuzz/`](fuzz/).
They need nightly and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cargo install cargo-fuzz --locked
cd fuzz
cargo +nightly fuzz run entry      -- -max_total_time=600
cargo +nightly fuzz run roundtrip  -- -max_total_time=600 -max_len=65536
cargo +nightly fuzz run glob       -- -max_total_time=120 -timeout=5
```

CI runs each for a minute as a smoke test; a real session is hours. If
a target finds something, turn the input into a unit test next to the
code it broke rather than committing the artifact.

On Windows the targets build with AddressSanitizer and need its runtime
DLL on `PATH` at run time; the one under Visual Studio's
`VC/Tools/MSVC/<ver>/bin/Hostx64/x64` works with a current nightly.

## Commit messages

- Subjects are **lowercase** and use a
  [conventional-commit](https://www.conventionalcommits.org/) prefix:
  `feat(codec): ...`, `fix(crypt): ...`, `docs: ...`, `build: ...`,
  `ci: ...`, `chore: ...`, `test: ...`.
- No attribution trailers of any kind (no `Co-Authored-By`, no signed-off-by
  lines, nothing). This applies to every commit in this repository,
  including ones authored with AI assistance.
- Keep the subject line under ~72 characters; use the body for the "why"
  if it's not obvious from the diff.

## Pull requests

- Keep PRs focused — one concern per PR is easier to review than a large
  mixed change.
- Update `CHANGELOG.md` under `[Unreleased]` for any user-visible change.
- Update `README.md` / doc comments if the public API or documented
  behavior changed.
- The PR template has a checklist; it mirrors the list above.

## Security issues

Please do **not** open a public issue for a suspected vulnerability — see
[`SECURITY.md`](SECURITY.md) for the private reporting channel and what's
in scope.

## License

By contributing, you agree that your contributions will be licensed under
the project's [MIT license](LICENSE-MIT).
