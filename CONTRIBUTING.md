# Contributing

Thanks for looking. A few things that make a change easy to take:

1. Open an issue first for anything larger than a bug fix, so we agree on the shape.
2. Keep the change focused - one behaviour per pull request.
3. Run the checks before opening the PR:
- gateway: `cd gateway && cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test`
- console: `npm --prefix console ci && npm --prefix console test`
4. Add a test for the behaviour you changed.
5. Match the surrounding style; the codebase is deliberately small and flat.
