# sigdiff

A differential test of signature checking. `tests/sigdiff.rs` runs `sig::verify` over recorded
cases and fails on any case where it disagrees with the stock Epicbox verifier (`epicboxlib
verifysignature`, the oracle). The relay must accept exactly the signatures the stock relay accepts.

## Files

- `tests/data/sigcases.jsonl`: generated cases with the oracle's answer, one JSON object per line
  (`pk`, `msg`, `sig`, `expected`). Throwaway keys only; checked in.
- `src/bin/sigdiff-gen.rs`: builds cases and records the oracle's answer for each.
- `tests/sigdiff.rs`: the test. It also checks an optional corpus of real cases given in
  `$SIGDIFF_CORPUS`, and skips that part when the variable is unset.

## Run the test

    cargo test --test sigdiff

## Regenerate the generated cases

Needs the `epicboxlib` binary from the stock Epicbox relay. It is looked up on `PATH`; `$ORACLE`
overrides the path.

    cargo run --bin sigdiff-gen -- gen tests/data/sigcases.jsonl

## Check a corpus of real signatures

Take the `slates` table from a dump of a Postgres-backed relay, build cases from it, and run the
test against them:

    pg_restore -a -t slates -f "$SCRATCH/slates.sql" <dump>
    cargo run --bin sigdiff-gen -- corpus "$SCRATCH/slates.sql" "$SCRATCH/corpus.jsonl"
    SIGDIFF_CORPUS="$SCRATCH/corpus.jsonl" cargo test --test sigdiff

`$SCRATCH` is any directory outside the repository. Keep the corpus file out of the repo: it holds
real addresses.
