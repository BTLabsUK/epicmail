#!/bin/sh
# Install or upgrade an epicmail relay from a GitHub release, with TLS through Caddy.
#
#   curl -fsSL https://raw.githubusercontent.com/BTLabsUK/epicmail/main/tools/get.sh | sh -s -- --domain relay.example.org
#
# It downloads the static binary for this machine and the install files of one release, checks
# every file against the release's SHA256SUMS, and runs that release's install.sh with them.
# Unless --no-tls, it installs Caddy and serves the relay as wss://DOMAIN. Run it again to
# upgrade; a run with nothing new changes nothing.
#
# Options:
#   --domain NAME     the domain wallets write in their addresses; needed on a first install
#   --version vX.Y.Z  the release to install (default: the latest)
#   --no-tls          set up no TLS proxy; put your own in front
#   --name, --prefix, --port, --listen, --no-backup, --no-start, --uninstall
#                     passed to install.sh (sh install.sh --help explains them)
#
# Needs Linux with systemd on x86_64 or aarch64, curl, sha256sum, and sudo unless run as root.
# EPICMAIL_REPO=owner/name installs from a fork. EPICMAIL_DOWNLOAD=URL takes the release files
# from URL/<file> instead (a mirror or a test). EPICMAIL_CADDY_TLS=internal makes Caddy use its
# own test certificate authority, for test machines without public DNS.
set -eu

REPO=${EPICMAIL_REPO:-BTLabsUK/epicmail}
die() { echo "get.sh: $*" >&2; exit 1; }
say() { echo "==> $*"; }
usage() {
  echo "usage: get.sh --domain relay.example.org [--version vX.Y.Z] [--no-tls] [install.sh options]"
  echo "The header of tools/get.sh in https://github.com/$REPO describes every option."
}

VERSION='' DOMAIN='' TLS=1 NAME=epicmail UNINSTALL=0
n=$#
while [ $n -gt 0 ]; do
  a=$1
  shift
  n=$((n - 1))
  case $a in
    --version | --domain | --name | --prefix | --port | --listen)
      [ $n -gt 0 ] || die "$a needs a value"
      v=$1
      shift
      n=$((n - 1))
      case $a in
        --version) VERSION=$v; continue ;;
        --domain) DOMAIN=$v ;;
        --name) NAME=$v ;;
      esac
      set -- "$@" "$a" "$v" ;;
    --no-tls) TLS=0 ;;
    --uninstall) UNINSTALL=1; set -- "$@" "$a" ;;
    --no-backup | --no-start) set -- "$@" "$a" ;;
    --bin | --static) die "$a belongs to tools/install.sh in a checkout" ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option $a (see --help)" ;;
  esac
done

[ "$(uname -s)" = Linux ] || die "this installs a systemd service on Linux"
case $(uname -m) in
  x86_64 | amd64) ARCH=x86_64 ;;
  aarch64 | arm64) ARCH=aarch64 ;;
  *) die "no release binary for $(uname -m); build from source instead (see the README)" ;;
esac
for c in curl sha256sum; do command -v $c >/dev/null 2>&1 || die "$c is needed"; done
if [ "$(id -u)" -eq 0 ]; then SUDO=''; else
  command -v sudo >/dev/null 2>&1 || die "run as root, or install sudo"
  SUDO=sudo
fi

# 1. Which release, and where its files are.
if [ -n "${EPICMAIL_DOWNLOAD:-}" ]; then
  BASE=${EPICMAIL_DOWNLOAD%/}
  VERSION=${VERSION:-"from $BASE"}
else
  if [ -z "$VERSION" ]; then
    url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") ||
      die "cannot reach github.com"
    VERSION=${url##*/}
  fi
  case $VERSION in v*) ;; *) VERSION=v$VERSION ;; esac
  case $VERSION in v[0-9]*) ;; *) die "no release found at https://github.com/$REPO/releases" ;; esac
  BASE=https://github.com/$REPO/releases/download/$VERSION
fi

# 2. Download, and check every file against SHA256SUMS before anything runs.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
BIN=epicmail-$ARCH-linux-musl
say "downloading epicmail $VERSION for $ARCH"
for f in SHA256SUMS "$BIN" install.sh epicmail.service epicmail.example.toml; do
  curl -fsSL -o "$TMP/$f" "$BASE/$f" || die "cannot download $BASE/$f"
done
(
  cd "$TMP"
  awk -v b="$BIN" '$2 == b || $2 == "install.sh" || $2 == "epicmail.service" || $2 == "epicmail.example.toml"' \
    SHA256SUMS >want
  [ "$(wc -l <want)" -eq 4 ] && sha256sum -c --quiet want
) || die "checksum mismatch: the files do not match SHA256SUMS of $VERSION. Nothing was installed."
say "checked against SHA256SUMS"

# install.sh expects a checkout's layout.
mkdir "$TMP/tools" "$TMP/packaging"
mv "$TMP/install.sh" "$TMP/tools/"
mv "$TMP/epicmail.service" "$TMP/epicmail.example.toml" "$TMP/packaging/"
chmod 0755 "$TMP/$BIN"

# 3. Install, upgrade or remove the relay.
EPICMAIL_GET=1 sh "$TMP/tools/install.sh" --bin "$TMP/$BIN" "$@"
[ $UNINSTALL = 0 ] || { say "Caddy, if this script installed it, is left as it is"; exit 0; }

CONF=/etc/$NAME/epicmail.toml
val() { $SUDO sed -n "s/^$1 = \"\([^\"]*\)\".*/\1/p" "$CONF" | head -n 1; }
DOMAIN=$(val domain)
LISTEN=$(val listen)
PORT=$($SUDO sed -n 's/^port = \([0-9]*\).*/\1/p' "$CONF" | head -n 1)
SITE=$DOMAIN
[ "${PORT:-443}" = 443 ] || SITE=$DOMAIN:$PORT
case $LISTEN in 0.0.0.0:*) LISTEN=127.0.0.1:${LISTEN##*:} ;; \[::\]:*) LISTEN=[::1]:${LISTEN##*:} ;; esac

if [ $TLS = 0 ]; then
  say "no TLS set up (--no-tls). Put a TLS proxy for $SITE in front of http://$LISTEN"
  say "(examples: https://github.com/$REPO/tree/main/packaging); wallets then use wss://$SITE"
  exit 0
fi

# 4. TLS with Caddy, without touching a web server that is already here.
site() {
  echo "# epicmail site: $DOMAIN"
  cat <<EOF
$SITE {
	# Websocket, /v1 and the public GET routes go to the relay; /metrics stays private.
	@metrics path /metrics /metrics/*
	respond @metrics 404
	reverse_proxy $LISTEN {
		# Wallets hold a socket open up to an hour: never lower this.
		transport http {
			read_timeout 3600s
			write_timeout 3600s
		}
	}
EOF
  [ "${EPICMAIL_CADDY_TLS:-}" != internal ] || printf '\ttls internal\n'
  echo "}"
}
CF=/etc/caddy/Caddyfile
MARK="# Managed by epicmail get.sh. Sites below are added by it; edit freely."

if [ -f $CF ] && grep -qx "# epicmail site: $DOMAIN" $CF; then
  say "Caddy already serves $DOMAIN"
elif [ -f $CF ] && [ "$(head -n 1 $CF)" = "$MARK" ]; then
  say "adding $DOMAIN to $CF"
  { echo; site; } | $SUDO tee -a $CF >/dev/null
  $SUDO caddy validate --config $CF --adapter caddyfile >/dev/null 2>&1 || die "Caddy refuses $CF; check it with: caddy validate --config $CF"
  $SUDO systemctl reload caddy
else
  other=''
  for p in caddy nginx apache2 httpd haproxy; do
    if command -v $p >/dev/null 2>&1; then other=$p; break; fi
  done
  if [ -z "$other" ] && command -v ss >/dev/null 2>&1 && [ -n "$(ss -ltnH '( sport = :80 or sport = :443 )')" ]; then
    other="a program listening on port 80 or 443"
  fi
  if [ -n "$other" ]; then
    say "found $other here, so it is left alone. Serve $SITE over TLS and proxy it to"
    say "http://$LISTEN with websocket upgrade and a one-hour read timeout. For Caddy, add:"
    echo
    site
    echo
    say "nginx: https://github.com/$REPO/blob/main/packaging/nginx.example.conf"
    exit 0
  fi

  say "installing Caddy from its official repository"
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -q
    $SUDO apt-get install -yq curl gnupg
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key |
      $SUDO gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt |
      $SUDO tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    $SUDO chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
    $SUDO apt-get update -q
    $SUDO apt-get install -yq caddy
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y 'dnf-command(copr)'
    $SUDO dnf copr enable -y @caddy/caddy
    $SUDO dnf install -y caddy
  else
    die "the relay is installed, but Caddy is not: install it by hand (https://caddyserver.com/docs/install) and run this again, or use --no-tls"
  fi
  { echo "$MARK"; echo; site; } | $SUDO tee $CF >/dev/null
  $SUDO caddy validate --config $CF --adapter caddyfile >/dev/null 2>&1 || die "Caddy refuses $CF; check it with: caddy validate --config $CF"
  $SUDO systemctl enable --quiet caddy
  $SUDO systemctl restart caddy
fi

cat <<EOF

The relay is ready. Wallets use:
  epicbox domain $DOMAIN, port ${PORT:-443}  (wss://$SITE)

Caddy gets the certificate on its own once $DOMAIN points at this machine and ports 80 and 443
are open. Logs: journalctl -u $NAME -f (relay), journalctl -u caddy -f (TLS).
EOF
