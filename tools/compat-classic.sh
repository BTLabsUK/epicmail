#!/usr/bin/env bash
# Compatibility run with a real classic epic-wallet CLI against two local relays.
#
# Needs a local Epic network with two funded wallets (the layout of a usernet "stable network":
# $NET/env.sh defines ALICE_DIR, BOB_DIR, ALICE_PW, BOB_PW and the node API port; both wallets have
# epicbox_domain = "localhost", epicbox_port = 3423, epicbox_protocol_unsecure = true).
#
# Relay A is localhost:3423, relay B is 127.0.0.1:3424; each lists the other in federation.peers.
#
#   same      alice and bob both on A: send, receive, reply, finalize
#   offline   bob not listening; relay A restarted while the slate waits; bob collects it later
#   federate  bob on B: A forwards the slate to B, B forwards the reply to A
#
# Env: RELAY_BIN, CFG_A, CFG_B, WALLET_BIN (classic wallet), NET, WORK.
# Usage: tools/compat-classic.sh [same|offline|federate|all]

set -u

RELAY_BIN="${RELAY_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug/epicmail}"
WALLET_BIN="${WALLET_BIN:?set WALLET_BIN to a classic epic-wallet binary}"
NET="${NET:?set NET to the local network directory}"
CFG_A="${CFG_A:?}"
CFG_B="${CFG_B:?}"
WORK="${WORK:?set WORK to a scratch directory}"
AMOUNT_BASE="${AMOUNT_BASE:-0.1}"
WAIT_S="${WAIT_S:-120}"

# shellcheck disable=SC1091
source "$NET/env.sh"
mkdir -p "$WORK"

PASSED=0
FAILED=0
ok()   { PASSED=$((PASSED + 1)); printf '  ok    %s\n' "$*"; }
bad()  { FAILED=$((FAILED + 1)); printf '  FAIL  %s\n' "$*"; }
info() { printf '        %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

wal() {
    local name="$1"; shift
    local dir pw
    case "$name" in
        alice) dir="$ALICE_DIR"; pw="$ALICE_PW" ;;
        bob)   dir="$BOB_DIR";   pw="$BOB_PW" ;;
    esac
    ( cd "$dir" && timeout 300 "$WALLET_BIN" --usernet -p "$pw" "$@" )
}

relay_pid_a=""
relay_pid_b=""
start_relay() {
    local which="$1" cfg log
    if [ "$which" = a ]; then cfg="$CFG_A"; else cfg="$CFG_B"; fi
    log="$WORK/relay-$which.log"
    "$RELAY_BIN" --config "$cfg" serve >>"$log" 2>&1 &
    local pid=$!
    if [ "$which" = a ]; then relay_pid_a=$pid; else relay_pid_b=$pid; fi
    local port
    port="$(grep -E '^listen' "$cfg" | grep -oE '[0-9]+"' | tr -d '"')"
    for _ in $(seq 1 50); do
        curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    bad "relay $which did not come up (see $log)"
    return 1
}
stop_relay() {
    local which="$1" pid
    if [ "$which" = a ]; then pid="$relay_pid_a"; else pid="$relay_pid_b"; fi
    [ -n "$pid" ] || return 0
    kill -TERM "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    if [ "$which" = a ]; then relay_pid_a=""; else relay_pid_b=""; fi
}

declare -A LISTENER
start_listener() {
    local name="$1" log="$WORK/$1.listen.log"
    if [ -n "${LISTENER[$name]:-}" ] && kill -0 "${LISTENER[$name]}" 2>/dev/null; then return 0; fi
    # The log is kept across restarts (expect_flow counts lines in it); only new lines are waited on.
    local start=1
    [ -f "$log" ] && start=$(( $(wc -l <"$log") + 1 ))
    local dir pw
    case "$name" in
        alice) dir="$ALICE_DIR"; pw="$ALICE_PW" ;;
        bob)   dir="$BOB_DIR";   pw="$BOB_PW" ;;
    esac
    ( cd "$dir" && exec "$WALLET_BIN" --usernet -p "$pw" listen -m epicbox ) >>"$log" 2>&1 &
    LISTENER[$name]=$!
    for _ in $(seq 1 60); do
        tail -n +"$start" "$log" | grep -q 'Starting epicbox subscription' && return 0
        sleep 0.5
    done
    bad "$name's epicbox listener did not subscribe (see $log)"
    return 1
}
stop_listener() {
    local pid="${LISTENER[$1]:-}"
    [ -n "$pid" ] || return 0
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    LISTENER[$1]=""
}

wait_log() { # file pattern seconds
    local i
    for i in $(seq 1 "$3"); do
        grep -qE "$2" "$1" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

key_of() { # wallet -> epicbox public key
    wal "$1" address 2>/dev/null | grep -A2 '^Epicbox address' | grep -oE '^[1-9A-HJ-NP-Za-km-z]{50,54}' | head -1
}

set_bob_relay() { # domain port
    local cfg="$BOB_DIR/epic-wallet.toml"
    [ -f "$WORK/bob.toml.orig" ] || cp "$cfg" "$WORK/bob.toml.orig"
    sed -i -e "s/^epicbox_domain = .*/epicbox_domain = \"$1\"/" -e "s/^epicbox_port = .*/epicbox_port = $2/" "$cfg"
}
restore_bob() {
    [ -f "$WORK/bob.toml.orig" ] && cp "$WORK/bob.toml.orig" "$BOB_DIR/epic-wallet.toml" && rm -f "$WORK/bob.toml.orig"
}

# A transfer from alice to `dest`; bob's listener log and alice's listener log are checked.
transfer() { # tag dest amount
    local tag="$1" dest="$2" amount="$3"
    wal alice send -m epicbox -d "$dest" -c 1 "$amount" >"$WORK/$tag.send.log" 2>&1
    if grep -qE "completed successfully" "$WORK/$tag.send.log"; then
        ok "$tag: alice's send to $dest was accepted by the relay"
    else
        bad "$tag: alice's send failed"; tail -5 "$WORK/$tag.send.log" | sed 's/^/        /'; return 1
    fi
}
expect_flow() { # tag before_bob before_alice
    local tag="$1" bb="$2" ba="$3" i n
    for i in $(seq 1 "$WAIT_S"); do
        n="$(count 'Receive new transaction' "$WORK/bob.listen.log")"
        [ "${n:-0}" -gt "$bb" ] && break
        sleep 1
    done
    if [ "${n:-0}" -gt "$bb" ]; then ok "$tag: bob's listener received the slate (${i}s)"; else bad "$tag: bob never received the slate"; return 1; fi
    for i in $(seq 1 "$WAIT_S"); do
        n="$(count 'finalized successfully' "$WORK/alice.listen.log")"
        [ "${n:-0}" -gt "$ba" ] && break
        sleep 1
    done
    if [ "${n:-0}" -gt "$ba" ]; then ok "$tag: alice's listener got the reply and finalized (${i}s)"; else bad "$tag: alice never finalized"; return 1; fi
}
count() { # pattern file -> number of matching lines (0 when the file is missing)
    local n
    n="$(grep -c "$1" "$2" 2>/dev/null)"
    printf '%s' "${n:-0}"
}
counts() {
    printf '%s %s' "$(count 'Receive new transaction' "$WORK/bob.listen.log")" \
        "$(count 'finalized successfully' "$WORK/alice.listen.log")"
}

cleanup() { stop_listener alice; stop_listener bob; stop_relay a; stop_relay b; restore_bob; }
trap cleanup EXIT

step "setup"
"$WALLET_BIN" --version | sed 's/^/        /'
"$RELAY_BIN" --version | sed 's/^/        /'
start_relay a || exit 1
start_relay b || exit 1
ALICE_KEY="$(key_of alice)"; BOB_KEY="$(key_of bob)"
[ -n "$ALICE_KEY" ] && [ -n "$BOB_KEY" ] || { bad "could not read the wallets' epicbox addresses"; exit 1; }
info "alice $ALICE_KEY"
info "bob   $BOB_KEY"
first="$(curl -fsS http://127.0.0.1:3423/status.json 2>/dev/null | head -c 200)"
info "relay A status: $first"

same() {
    step "same: both wallets on relay A"
    start_listener alice; start_listener bob
    read -r bb ba <<<"$(counts)"
    transfer same "$BOB_KEY@localhost:3423" "${AMOUNT_BASE}1" && expect_flow same "$bb" "$ba"
    stop_listener bob
}

offline() {
    step "offline: bob away, relay restarted while the slate waits"
    stop_listener bob
    start_listener alice 2>/dev/null || true
    read -r bb ba <<<"$(counts)"
    transfer offline "$BOB_KEY@localhost:3423" "${AMOUNT_BASE}2" || return
    sleep 2
    w="$(curl -fsS http://127.0.0.1:3423/status.json | grep -oE '"messages_waiting":[0-9]+' | grep -oE '[0-9]+$')"
    if [ "${w:-0}" -ge 1 ]; then ok "offline: relay A holds the slate ($w waiting)"; else bad "offline: relay A reports nothing waiting"; fi
    stop_relay a; start_relay a || return
    ok "offline: relay A restarted"
    start_listener bob
    expect_flow offline "$bb" "$ba"
    stop_listener bob
}

federate() {
    step "federate: bob on relay B, alice on relay A"
    stop_listener bob
    set_bob_relay 127.0.0.1 3424
    start_listener alice 2>/dev/null || true
    start_listener bob
    read -r bb ba <<<"$(counts)"
    transfer federate "$BOB_KEY@127.0.0.1:3424" "${AMOUNT_BASE}3" && expect_flow federate "$bb" "$ba"
    grep -q 'forwarded' "$WORK/relay-a.log" && ok "federate: relay A logged a forward" || bad "federate: no forward in relay A's log"
    grep -q 'forwarded' "$WORK/relay-b.log" && ok "federate: relay B logged a forward (the reply)" || bad "federate: no forward in relay B's log"
    stop_listener bob
    restore_bob
}

case "${1:-all}" in
    same) same ;;
    offline) offline ;;
    federate) federate ;;
    all) same; offline; federate ;;
esac

printf '\n%s passed, %s failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
