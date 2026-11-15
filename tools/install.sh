#!/bin/sh
# Install epicmail from this checkout as a systemd service on Linux, or upgrade or remove it.
#
#   tools/install.sh --domain relay.example.org   first install: build, configure, start
#   tools/install.sh                              upgrade: back up, build, check, replace, restart
#   tools/install.sh --uninstall                  remove the service and binary, keep config and data
#
# Options:
#   --domain NAME   server.domain of a new config: the domain wallets write in their addresses
#   --port N        server.port of a new config: the port wallets write (default 443)
#   --listen ADDR   server.listen of a new config (default 127.0.0.1:3423)
#   --bin FILE      install this binary instead of building one
#   --static        build the static musl binary (tools/build-static.sh)
#   --name NAME     service name, also /etc/NAME and /var/lib/NAME (default epicmail)
#   --prefix DIR    install the binary as DIR/bin/epicmail (default /usr/local)
#   --no-backup     on upgrade, do not back up the store first
#   --no-start      install and enable, but do not start or restart
#   --uninstall     stop and remove the service and its binary; config and data stay
#
# Run it as your own user: it builds with cargo and uses sudo only to install. An existing config
# is never changed, and a run with nothing new to install changes nothing. Needs Linux with
# systemd, rustup (unless --bin), sudo and curl. With sqlite3 the upgrade backup is taken while
# the relay runs; without it the relay is stopped for the copy.
set -eu

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "==> $*"; }
need() { [ "$2" -ge 2 ] || die "$1 needs a value"; }

cd "$(dirname "$0")/.."
[ -f packaging/epicmail.service ] && [ -f packaging/epicmail.example.toml ] ||
  die "run it from an epicmail checkout"

NAME=epicmail PREFIX=/usr/local DOMAIN='' PORT='' LISTEN='' BIN=''
STATIC=0 BACKUP=1 START=1 UNINSTALL=0
while [ $# -gt 0 ]; do
  case $1 in
    --domain) need "$1" $#; DOMAIN=$2; shift 2 ;;
    --port) need "$1" $#; PORT=$2; shift 2 ;;
    --listen) need "$1" $#; LISTEN=$2; shift 2 ;;
    --bin) need "$1" $#; BIN=$2; shift 2 ;;
    --name) need "$1" $#; NAME=$2; shift 2 ;;
    --prefix) need "$1" $#; PREFIX=${2%/}; shift 2 ;;
    --static) STATIC=1; shift ;;
    --no-backup) BACKUP=0; shift ;;
    --no-start) START=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h | --help) sed -n '2,/^set -eu/{/^set -eu/d;s/^# \{0,1\}//;p;}' "$0"; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

case $NAME in '' | -* | *[!a-z0-9-]*) die "--name takes lowercase letters, digits and -" ;; esac
case $DOMAIN in *[!A-Za-z0-9.-]*) die "--domain takes a host name, such as relay.example.org" ;; esac
case $PORT in *[!0-9]*) die "--port takes a number" ;; esac
case $LISTEN in *[!]0-9A-Fa-f.:[]*) die "--listen takes an address and port, such as 127.0.0.1:3423" ;; esac
case $PREFIX in /*) ;; *) die "--prefix must be an absolute path" ;; esac
case $PREFIX/ in /home/* | /root/* | /tmp/*) die "--prefix: the service cannot see $PREFIX (ProtectHome, PrivateTmp)" ;; esac

[ "$(uname -s)" = Linux ] || die "this installs a systemd service on Linux; see docs/operating.md for others"
[ -d /run/systemd/system ] || die "systemd is not running here"
if [ "$(id -u)" -eq 0 ]; then SUDO=''; else
  command -v sudo >/dev/null 2>&1 || die "sudo is needed for the install steps"
  SUDO=sudo
fi

ETC=/etc/$NAME
CONF=$ETC/epicmail.toml
UNIT=/etc/systemd/system/$NAME.service
DEST=$PREFIX/bin/epicmail

if [ $UNINSTALL = 1 ]; then
  say "stopping and removing $NAME.service"
  $SUDO systemctl disable --now "$NAME" 2>/dev/null || true
  $SUDO rm -f "$UNIT" "$UNIT.bak"
  $SUDO systemctl daemon-reload
  if grep -qs "^ExecStart=$DEST " /etc/systemd/system/*.service; then
    say "kept $DEST: another service runs it"
  else
    $SUDO rm -f "$DEST"
  fi
  say "kept $ETC (config), /var/lib/private/$NAME (data) and /var/backups/$NAME;"
  say "remove them by hand when no longer needed"
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# 1. The binary, built as this user.
if [ -z "$BIN" ]; then
  command -v cargo >/dev/null 2>&1 ||
    die "cargo not found: install Rust with rustup (https://rustup.rs), or pass --bin FILE"
  if [ $STATIC = 1 ]; then
    tools/build-static.sh
    BIN=target/x86_64-unknown-linux-musl/release/epicmail
  else
    say "building (cargo build --release)"
    cargo build --release --locked --bin epicmail
    BIN=target/release/epicmail
  fi
fi
[ -f "$BIN" ] && [ -x "$BIN" ] || die "$BIN is not an executable file"
VERSION=$("$BIN" --version) || die "$BIN does not run on this host"
say "installing $VERSION as $NAME"

# 2. The config: a new one from the example, or the existing one checked by the new binary.
if $SUDO test -e "$CONF"; then
  NEWCONF=0
  [ -z "$DOMAIN$PORT$LISTEN" ] || say "note: $CONF exists and is kept; --domain, --port and --listen are not applied"
  $SUDO cat "$CONF" >"$TMP/epicmail.toml"
else
  NEWCONF=1
  [ -n "$DOMAIN" ] || die "a first install needs --domain: the domain wallets write in their addresses"
  sed -e "s|^domain = \"[^\"]*\"|domain = \"$DOMAIN\"|" \
    -e "s|^path = \"[^\"]*\"|path = \"/var/lib/$NAME/epicmail.db\"|" \
    packaging/epicmail.example.toml >"$TMP/epicmail.toml"
  [ -z "$PORT" ] || sed -i "s|^port = [0-9]*|port = $PORT|" "$TMP/epicmail.toml"
  [ -z "$LISTEN" ] || sed -i "s|^listen = \"[^\"]*\"|listen = \"$LISTEN\"|" "$TMP/epicmail.toml"
  grep -q "^domain = \"$DOMAIN\"" "$TMP/epicmail.toml" &&
    grep -q "^path = \"/var/lib/$NAME/epicmail.db\"" "$TMP/epicmail.toml" ||
    die "packaging/epicmail.example.toml changed shape; set up $CONF by hand"
fi
"$BIN" check-config --config "$TMP/epicmail.toml" >"$TMP/check.out" 2>&1 ||
  { cat "$TMP/check.out" >&2; die "the config does not pass check-config with the new binary"; }

val() { sed -n "s/^$1 = \"\([^\"]*\)\".*/\1/p" "$TMP/epicmail.toml" | head -n 1; }
LISTEN_AT=$(val listen)
STORE=$(val path)

sed -e "s|^ExecStart=.*|ExecStart=$DEST serve --config $CONF|" \
  -e "s|/var/lib/epicmail/|/var/lib/$NAME/|" \
  -e "s|^StateDirectory=.*|StateDirectory=$NAME|" \
  -e "s|^ConfigurationDirectory=.*|ConfigurationDirectory=$NAME|" \
  -e "s|^SyslogIdentifier=.*|SyslogIdentifier=$NAME|" \
  packaging/epicmail.service >"$TMP/unit"

ACTIVE=0
$SUDO systemctl is-active --quiet "$NAME" 2>/dev/null && ACTIVE=1
if [ $NEWCONF = 0 ] && [ $ACTIVE = 1 ] && $SUDO cmp -s "$BIN" "$DEST" && $SUDO cmp -s "$TMP/unit" "$UNIT"; then
  say "$NAME is up to date ($VERSION); nothing to do"
  exit 0
fi

# 3. A backup of the store before an upgrade replaces the binary: online with sqlite3, or else
# a copy of the stopped store (the restart below follows anyway).
if [ $NEWCONF = 0 ] && [ $BACKUP = 1 ] && [ -n "$STORE" ] && $SUDO test -f "$STORE"; then
  OUT=/var/backups/$NAME/epicmail-$(date -u +%Y%m%dT%H%M%SZ).db
  say "backing up the store to $OUT"
  $SUDO install -d -m 0700 "/var/backups/$NAME"
  if command -v sqlite3 >/dev/null 2>&1; then
    $SUDO sqlite3 "$STORE" ".backup '$OUT'"
    $SUDO chmod 0600 "$OUT"
  else
    if [ $ACTIVE = 1 ]; then
      say "no sqlite3: stopping $NAME for the copy"
      $SUDO systemctl stop "$NAME"
      START=1
    fi
    for s in "" -wal; do
      if $SUDO test -f "$STORE$s"; then $SUDO cp "$STORE$s" "$OUT$s" && $SUDO chmod 0600 "$OUT$s"; fi
    done
  fi
fi

# 4. Files in place. The binary is swapped by rename, so a running relay is not disturbed.
$SUDO install -d -m 0755 "$PREFIX/bin" "$ETC"
[ $NEWCONF = 0 ] || $SUDO install -m 0644 "$TMP/epicmail.toml" "$CONF"
$SUDO install -m 0755 "$BIN" "$DEST.new"
$SUDO mv -f "$DEST.new" "$DEST"

if $SUDO test -f "$UNIT" && ! $SUDO cmp -s "$TMP/unit" "$UNIT"; then
  say "replacing $UNIT (the old one is $UNIT.bak; put local changes in a drop-in instead)"
  $SUDO cp "$UNIT" "$UNIT.bak"
fi
$SUDO install -m 0644 "$TMP/unit" "$UNIT"
$SUDO systemctl daemon-reload
$SUDO systemctl enable --quiet "$NAME"

if [ $START = 0 ]; then
  say "installed and enabled; start it with: sudo systemctl start $NAME"
  exit 0
fi

# 5. Start, and wait until /ready answers.
if [ $ACTIVE = 1 ]; then say "restarting $NAME"; else say "starting $NAME"; fi
$SUDO systemctl restart "$NAME"
case $LISTEN_AT in
  0.0.0.0:*) PROBE=127.0.0.1:${LISTEN_AT##*:} ;;
  \[::\]:*) PROBE=[::1]:${LISTEN_AT##*:} ;;
  *) PROBE=$LISTEN_AT ;;
esac
if command -v curl >/dev/null 2>&1; then
  i=0
  until curl -fsS -g -o /dev/null "http://$PROBE/ready" 2>/dev/null; do
    i=$((i + 1))
    if [ $i -ge 30 ]; then
      $SUDO journalctl -u "$NAME" -n 30 --no-pager >&2 || true
      die "$NAME did not become ready at http://$PROBE/ready"
    fi
    sleep 1
  done
  say "$NAME is ready at http://$PROBE"
else
  say "curl not found; check it with: systemctl status $NAME"
fi

# tools/get.sh sets up TLS itself and prints its own next steps.
if [ $NEWCONF = 1 ] && [ -z "${EPICMAIL_GET:-}" ]; then
  cat <<EOF

Next:
  - Put a reverse proxy with TLS in front: packaging/nginx.example.conf or
    packaging/Caddyfile.example. Wallets connect to wss://$DOMAIN.
  - List that proxy in server.trusted_proxies in $CONF (127.0.0.1/32 is set).
  - Logs: journalctl -u $NAME -f. Operating guide: docs/operating.md.
EOF
fi
