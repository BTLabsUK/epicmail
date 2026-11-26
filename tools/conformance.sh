#!/bin/sh
# Run the Epicmail conformance suite against a mailbox.
#
#   tools/conformance.sh HOST [--staging] [--expect-fail FILE] [--skip-slow] [--other HOST] ...
#   tools/conformance.sh --url http://127.0.0.1:3423 --domain a.test --other-url http://127.0.0.1:3424 --other-domain b.test --staging
#
# Builds examples/conformance (release) and runs it; every argument goes to the program
# (see `conformance --help`). Exit 1 when a case fails that is not in the --expect-fail file, or
# when a case in it passes. Expected failures per mailbox are kept in tools/conformance-expect/.
set -eu
cd "$(dirname "$0")/.."
# EPICMAIL_HEAVY: an optional wrapper command for heavy builds (for example a job queue).
${EPICMAIL_HEAVY:-} cargo build --release --example conformance
exec target/release/examples/conformance "$@"
