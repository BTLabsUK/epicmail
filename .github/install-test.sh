#!/bin/bash
# Install test for tools/get.sh on a fresh CI runner (systemd, passwordless sudo):
#   1. a download that does not match SHA256SUMS is refused and installs nothing;
#   2. a first install brings up the relay and Caddy, and wss://DOMAIN reaches the relay;
#   3. running it again changes nothing; with a different binary it backs up and upgrades;
#   4. a second relay is added to the Caddyfile get.sh manages;
#   5. a Caddyfile get.sh does not manage is left alone;
#   6. --uninstall removes a relay and leaves the others running.
# With TAG=vX.Y.Z it installs the published release with the one-line command. Without TAG it
# serves the files in dist/ (the release files the workflow built) on 127.0.0.1.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GITHUB_REPOSITORY:?}"
ARCH=$(uname -m)
step() { printf '\n### %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
code() { curl -sk -o /dev/null -w '%{http_code}' "$@" || true; }
via_caddy() { code --resolve "$1:443:127.0.0.1" "https://$1$2"; }
ws_caddy() {
  code --http1.1 -m 3 --resolve "$1:443:127.0.0.1" -H "Connection: Upgrade" -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "https://$1/"
}
wait_for() { # wait_for WANT CMD...: retry CMD for 30 s until it prints WANT
  local want=$1 got=''
  shift
  for _ in $(seq 30); do
    got=$("$@")
    [ "$got" = "$want" ] && return 0
    sleep 1
  done
  fail "$* gave $got, not $want"
}

step "a fresh machine: no web server"
for s in nginx apache2; do sudo systemctl disable --now "$s" >/dev/null 2>&1 || true; done
sudo apt-get purge -yq 'nginx*' 'apache2*' >/dev/null 2>&1 || true
! command -v nginx >/dev/null || fail "nginx is still installed"
[ -z "$(ss -ltnH '( sport = :80 or sport = :443 )')" ] || fail "something listens on port 80 or 443"
[ ! -e /usr/local/bin/epicmail ] || fail "epicmail is already installed"
echo "sqlite3: $(command -v sqlite3 || echo none)"

chmod +x dist/epicmail-*
mkdir -p bad && cp dist/* bad/ && printf x >>"bad/epicmail-$ARCH-linux-musl"
python3 -m http.server --bind 127.0.0.1 --directory dist 8099 >/dev/null 2>&1 &
python3 -m http.server --bind 127.0.0.1 --directory bad 8098 >/dev/null 2>&1 &
sleep 1

export EPICMAIL_REPO=$GITHUB_REPOSITORY EPICMAIL_CADDY_TLS=internal
if [ -n "${TAG:-}" ]; then
  get() { curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPOSITORY/$TAG/tools/get.sh" | sh -s -- --version "$TAG" "$@"; }
else
  get() { EPICMAIL_DOWNLOAD=http://127.0.0.1:8099 sh tools/get.sh "$@"; }
fi

step "1. a tampered binary is refused"
if out=$(EPICMAIL_DOWNLOAD=http://127.0.0.1:8098 sh tools/get.sh --domain relay.example.org 2>&1); then
  echo "$out"
  fail "a tampered download was installed"
fi
echo "$out"
grep -q "checksum mismatch" <<<"$out" || fail "no checksum message"
[ ! -e /usr/local/bin/epicmail ] && [ ! -e /etc/epicmail ] || fail "something was installed"

step "2. first install with TLS"
get --domain relay.example.org
systemctl is-active --quiet epicmail || fail "epicmail is not running"
systemctl is-active --quiet caddy || fail "caddy is not running"
/usr/local/bin/epicmail --version
if [ -n "${TAG:-}" ]; then
  [ "$(/usr/local/bin/epicmail --version)" = "epicmail ${TAG#v}" ] || fail "installed version is not $TAG"
fi
[ "$(code http://127.0.0.1:3423/ready)" = 200 ] || fail "relay /ready"
wait_for 200 via_caddy relay.example.org /ready
[ "$(via_caddy relay.example.org /metrics)" = 404 ] || fail "/metrics is public through Caddy"
[ "$(ws_caddy relay.example.org)" = 101 ] || fail "no websocket upgrade through Caddy"
curl -sk --resolve relay.example.org:443:127.0.0.1 https://relay.example.org/status.json | grep -q '"store_ok":true' ||
  fail "status.json through Caddy"

step "3a. running it again changes nothing"
pid=$(systemctl show -p MainPID --value epicmail)
cf=$(sha256sum /etc/caddy/Caddyfile)
out=$(get 2>&1)
echo "$out"
grep -q "up to date" <<<"$out" || fail "no up-to-date message"
grep -q "Caddy already serves relay.example.org" <<<"$out" || fail "Caddy site not recognised"
[ "$(systemctl show -p MainPID --value epicmail)" = "$pid" ] || fail "the relay was restarted"
[ "$(sha256sum /etc/caddy/Caddyfile)" = "$cf" ] || fail "the Caddyfile changed"

step "3b. a different installed binary is backed up and upgraded"
printf x | sudo tee -a /usr/local/bin/epicmail >/dev/null
get
[ "$(systemctl show -p MainPID --value epicmail)" != "$pid" ] || fail "the relay was not restarted"
sudo ls /var/backups/epicmail/ | grep -q '^epicmail-.*\.db$' || fail "no backup"
sudo cmp -s "dist/epicmail-$ARCH-linux-musl" /usr/local/bin/epicmail || fail "the binary was not replaced"
wait_for 200 via_caddy relay.example.org /ready

step "4. a second relay joins the managed Caddyfile"
get --name relay-two --listen 127.0.0.1:3424 --domain two.example.org
wait_for 200 via_caddy two.example.org /ready
[ "$(via_caddy relay.example.org /ready)" = 200 ] || fail "the first site broke"
curl -sk --resolve two.example.org:443:127.0.0.1 https://two.example.org/status.json | grep -q '"identity":"two.example.org:443"' ||
  fail "two.example.org reaches the wrong relay"

step "5. a Caddyfile get.sh does not manage is left alone"
sudo sed -i 1d /etc/caddy/Caddyfile
cf=$(sha256sum /etc/caddy/Caddyfile)
out=$(get --name relay-three --listen 127.0.0.1:3425 --domain three.example.org 2>&1)
echo "$out"
grep -q "left alone" <<<"$out" || fail "no left-alone message"
grep -q "three.example.org {" <<<"$out" || fail "no site to add was printed"
[ "$(sha256sum /etc/caddy/Caddyfile)" = "$cf" ] || fail "the Caddyfile changed"
[ "$(code http://127.0.0.1:3425/ready)" = 200 ] || fail "relay-three /ready"

step "6. uninstall one relay"
get --uninstall --name relay-three
! systemctl is-active --quiet relay-three || fail "relay-three still runs"
[ ! -e /etc/systemd/system/relay-three.service ] || fail "relay-three unit still there"
systemctl is-active --quiet epicmail && systemctl is-active --quiet relay-two || fail "another relay stopped"
[ -x /usr/local/bin/epicmail ] || fail "the shared binary was removed"

step "all install tests passed on $ARCH"
