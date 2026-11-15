#!/bin/bash
# Runs ON the relay host (uploaded and called by tools/ship; not meant to be run by hand,
# except `ship-deploy.sh rollback`).
#
#   ship-deploy.sh deploy NEWBIN [--landing]   swap in NEWBIN, restart, check, roll back on failure
#   ship-deploy.sh rollback [--landing]        swap /usr/local/bin/epicmail with its .prev, restart, check
#
# Exit: 0 live and healthy | 3 health failed, rolled back to the previous binary and healthy
#       4 preflight failed, nothing changed | 5 health failed and the rollback failed too.
#
# The swap is a rename inside /usr/local/bin, so it is atomic. The previous binary stays as
# epicmail.prev (a hard link to the old inode, kept only when the new binary differs).
set -u
BIN=/usr/local/bin/epicmail
PREV=$BIN.prev
CONF=${EPICMAIL_CONF:-/etc/epicmail/epicmail.toml}
UNIT=${EPICMAIL_UNIT:-epicmail}
USER_=${EPICMAIL_USER:-epicmail}
HERE=$(cd "$(dirname "$0")" && pwd)

mode=${1:-}; shift || true
NEW=""; LANDING=""
[ "$mode" = deploy ] && { NEW=${1:-}; shift || true; }
for a in "$@"; do [ "$a" = --landing ] && LANDING=--landing; done

now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.1f", b-a}'; }
say() { echo "[host] $*"; }
sha() { sudo sha256sum "$1" | cut -c1-12; }

LISTEN=$(sudo awk -F'"' '/^[[:space:]]*listen[[:space:]]*=/{print $2; exit}' "$CONF")
URL=http://${LISTEN:-127.0.0.1:13481}

# health SINCE_EPOCH EXPECT_SHA: 0 healthy, 1 not
health() {
  local t0=$1 want=$2 i
  # Wait for the relay to answer: up to 25 s.
  # Stop waiting at once if the unit has died or restarted itself: no need to sit out 25 s.
  for i in $(seq 1 100); do
    curl -fsS -m 2 -o /dev/null "$URL/ready" 2>/dev/null && break
    if [ "$(systemctl show -p NRestarts --value "$UNIT")" != 0 ] || \
       [ "$(systemctl show -p ActiveState --value "$UNIT")" = failed ]; then
      say "FAIL unit stopped or restarted itself before it answered"
      sudo journalctl -u "$UNIT" --since "@${t0%.*}" --no-pager -q 2>&1 | tail -5 | sed 's/^/[host] journal: /'
      return 1
    fi
    sleep 0.25
  done
  python3 "$HERE/ship-probe.py" "$URL" $LANDING --timeout 5 | sed 's/^/[probe] /'
  [ "${PIPESTATUS[0]}" = 0 ] || return 1
  sleep 3  # a crash loop or a late panic shows up in this window
  local active nr pid have errs
  active=$(systemctl is-active "$UNIT")
  nr=$(systemctl show -p NRestarts --value "$UNIT")
  pid=$(systemctl show -p MainPID --value "$UNIT")
  [ "$active" = active ] || { say "FAIL unit is $active"; return 1; }
  [ "$nr" = 0 ] || { say "FAIL unit restarted itself $nr time(s)"; return 1; }
  have=$(sudo sha256sum "/proc/$pid/exe" 2>/dev/null | cut -c1-12)
  [ "$have" = "$want" ] || { say "FAIL running binary is $have, expected $want"; return 1; }
  say "ok   running      pid $pid is $have, no self-restarts"
  errs=$(sudo journalctl -u "$UNIT" --since "@${t0%.*}" -p err --no-pager -q 2>&1)
  [ -z "$errs" ] || { say "FAIL journal has errors since the restart:"; echo "$errs" | head -8; return 1; }
  if sudo journalctl -u "$UNIT" --since "@${t0%.*}" --no-pager -q 2>&1 | grep -qi 'panicked'; then
    say "FAIL journal has a panic since the restart"; return 1
  fi
  say "ok   journal      no errors or panics since the restart"
}

restart() {
  local t=$(now)
  sudo systemctl reset-failed "$UNIT" 2>/dev/null
  sudo systemctl restart "$UNIT" || say "systemctl restart reported a failure"
  say "restart took $(since "$t") s"
}

# Put $1 (a file in /usr/local/bin) in place of $BIN, atomically.
put_in_place() {
  sudo ln -f "$1" "$BIN.swap" && sudo mv -f "$BIN.swap" "$BIN"
}

if [ "$mode" = rollback ]; then
  [ -x "$PREV" ] || { say "no $PREV to roll back to"; exit 4; }
  cur=$(sha "$BIN"); old=$(sha "$PREV")
  # swap: current becomes .prev so a second rollback undoes this one
  sudo ln -f "$BIN" "$BIN.cur" && put_in_place "$PREV" && sudo mv -f "$BIN.cur" "$PREV" || exit 4
  say "swapped: live is now $old, $PREV is $cur"
  t0=$(now); restart
  health "$t0" "$old" && { say "healthy after manual rollback"; exit 0; }
  say "FAIL after manual rollback"; exit 5
fi

[ "$mode" = deploy ] && [ -n "$NEW" ] && [ -f "$NEW" ] || { echo "usage: $0 deploy NEWBIN [--landing] | rollback" >&2; exit 4; }

# ---- preflight: nothing live is touched until the new binary starts and reads the config
T_ALL=$(now)
sudo install -m 0755 -o root -g root "$NEW" "$BIN.new" || exit 4
newsha=$(sha "$BIN.new"); cursha=$(sha "$BIN")
say "current $cursha -> new $newsha"
ver=$("$BIN.new" --version 2>&1) || { say "FAIL new binary does not run: $ver"; sudo rm -f "$BIN.new"; exit 4; }
say "new binary: $ver"
out=$(sudo -u "$USER_" "$BIN.new" check-config --config "$CONF" 2>&1) \
  || { say "FAIL check-config refused the live config: $out"; sudo rm -f "$BIN.new"; exit 4; }
say "check-config accepts the live config"

# ---- swap
if [ "$newsha" != "$cursha" ]; then
  sudo rm -f "$PREV.tmp"
  if [ "$BIN" -ef "$PREV" ]; then
    say "$PREV already is the live binary ($cursha)"   # after a rollback the two are one inode
  else
    sudo ln -f "$BIN" "$PREV.tmp" && sudo mv -f "$PREV.tmp" "$PREV" || exit 4
    say "previous binary kept as $PREV ($cursha)"
  fi
else
  say "new binary is identical to the live one; $PREV is left as it is"
fi
sudo mv -f "$BIN.new" "$BIN" || exit 4
T0=$(now)
restart
if health "$T0" "$newsha"; then
  say "DEPLOYED $newsha, total on host $(since "$T_ALL") s"
  exit 0
fi

# ---- automatic rollback
say "HEALTH FAILED: rolling back to the previous binary"
TR=$(now)
if [ "$newsha" = "$cursha" ] || [ ! -x "$PREV" ]; then
  say "no different previous binary to roll back to"; exit 5
fi
put_in_place "$PREV" || { say "rollback could not swap the binary"; exit 5; }
restart
if health "$TR" "$cursha"; then
  say "ROLLED BACK to $cursha in $(since "$TR") s; the failed binary $newsha is not live"
  exit 3
fi
say "ROLLBACK FAILED: the relay is not healthy on $cursha either; look at: journalctl -u $UNIT"
exit 5
