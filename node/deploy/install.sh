#!/bin/sh
# Install a Varve TESTNET node as a systemd service on Debian/Ubuntu.
#
#   curl -fsSL https://raw.githubusercontent.com/IsamuNagai/varve/main/node/deploy/install.sh -o install.sh
#   less install.sh                      # read it first
#   sudo sh install.sh                   # node only
#   sudo MINE=1 sh install.sh            # node + miner (uses all cores)
#
# Options (environment variables):
#   REF=<git commit or branch>  source to build (default: main)
#   MINE=1                      also mine; MINE_THREADS=N to limit cores
#   PORT=39900                  public P2P port
#   API=1                       serve the public read-only API (node/API.md) on
#                               127.0.0.1:39911, for a TLS proxy such as Caddy
#
# What it does: installs build tools, creates two unprivileged accounts
# ("varve-build" compiles, "varve" runs the node), builds the node from source
# (pinned C libraries are verified by tools/build-deps.sh), installs
# /usr/local/bin/varve and a hardened systemd service, and opens the P2P port
# if ufw is active. RPC stays on 127.0.0.1.
set -eu

REF="${REF:-main}"
PORT="${PORT:-39900}"
MINE="${MINE:-0}"
MINE_THREADS="${MINE_THREADS:-}"
API="${API:-0}"
REPO="https://github.com/IsamuNagai/varve.git"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
printf '%s' "$REF" | grep -Eq '^[A-Za-z0-9._/-]+$' || { echo "REF contains unsupported characters"; exit 1; }
printf '%s' "$PORT" | grep -Eq '^[0-9]+$' || { echo "PORT must be a number"; exit 1; }
[ -z "$MINE_THREADS" ] || printf '%s' "$MINE_THREADS" | grep -Eq '^[0-9]+$' || { echo "MINE_THREADS must be a number"; exit 1; }
command -v apt-get >/dev/null || { echo "this script supports Debian/Ubuntu (apt)"; exit 1; }

echo "== installing build tools"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q git cmake build-essential curl ca-certificates

# Two accounts: "varve-build" compiles (its files are never writable by the service),
# "varve" runs the node. A compromised node therefore cannot tamper with the next build.
if ! id varve-build >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /opt/varve-build --shell /usr/sbin/nologin varve-build
fi
if ! id varve >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/varve --shell /usr/sbin/nologin varve
fi
chmod 755 /opt/varve-build

echo "== installing Rust for the build account (rustup, stable)"
if [ ! -x /opt/varve-build/.cargo/bin/cargo ]; then
  runuser -u varve-build -- sh -c 'curl -fsSL https://sh.rustup.rs -o /tmp/rustup.sh && sh /tmp/rustup.sh -y --profile minimal --default-toolchain stable && rm -f /tmp/rustup.sh'
fi

echo "== building varve ($REF)"
runuser -u varve-build -- sh -c "
  set -eu
  cd /opt/varve-build
  [ -d src ] || git clone -q $REPO src
  cd src
  git fetch -q --prune origin
  # a full commit id is used as-is; anything else is taken from origin (never a stale local branch)
  if printf '%s' '$REF' | grep -Eq '^[0-9a-f]{40}$'; then git checkout -q --detach '$REF'; else git checkout -q --detach 'origin/$REF'; fi
  git log -1 --format='building commit %H'
  # build from a plain exported tree (no .git inside), independent of host git configuration
  rm -rf /opt/varve-build/build && mkdir /opt/varve-build/build
  git archive --format=tar HEAD | tar -x -C /opt/varve-build/build
  cd /opt/varve-build/build/node && /opt/varve-build/.cargo/bin/cargo build --release --locked -q
"
install -o root -g root -m 0755 /opt/varve-build/build/node/target/release/varve /usr/local/bin/varve
# never execute the freshly built binary as root
runuser -u varve -- /usr/local/bin/varve version

ARGS="node --network testnet --datadir /var/lib/varve/testnet --port $PORT"
if [ "$API" = "1" ]; then
  # loopback only; publish through a TLS reverse proxy (see node/README.md)
  ARGS="$ARGS --api-port 39911 --api-trust-proxy"
fi
if [ "$MINE" = "1" ]; then
  ARGS="$ARGS --mine"
  [ -n "$MINE_THREADS" ] && ARGS="$ARGS --threads $MINE_THREADS"
fi

echo "== installing systemd service"
cat > /etc/systemd/system/varve.service <<EOF
[Unit]
Description=Varve testnet node
After=network-online.target
Wants=network-online.target

[Service]
User=varve
Group=varve
ExecStart=/usr/local/bin/varve $ARGS
Restart=always
RestartSec=10
# hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/varve
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable varve
systemctl restart varve   # picks up a new binary on upgrade

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "$PORT"/tcp
fi

echo
echo "Varve testnet node installed and running."
echo "  status:   systemctl status varve"
echo "  logs:     journalctl -u varve -f"
echo "  info:     sudo -u varve varve rpc --datadir /var/lib/varve/testnet getblockchaininfo"
[ "$MINE" = "1" ] && echo "  mining:   sudo -u varve varve rpc --datadir /var/lib/varve/testnet getmininginfo"
echo "Make sure TCP port $PORT is open in your provider's firewall."
