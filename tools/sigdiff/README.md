# sigdiff

Regenerate the recorded oracle answers (needs the stock `epicboxlib` binary, `$ORACLE` overrides the path):

    cargo run --bin sigdiff-gen -- gen tests/data/sigcases.jsonl
    pg_restore -a -t slates -f "$SCRATCH/slates.sql" <dump>
    cargo run --bin sigdiff-gen -- corpus "$SCRATCH/slates.sql" "$SCRATCH/corpus.jsonl"
    SIGDIFF_CORPUS="$SCRATCH/corpus.jsonl" cargo test --test sigdiff

Keep the corpus file out of the repo: it holds real addresses.
