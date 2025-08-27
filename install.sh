#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   sudo scripts/install_pi.sh --repo https://github.com/you/wids.git --branch main --api-key 'secret' --device wlan0
REPO=""
BRANCH="main"
API_KEY="CHANGE-ME"
DEVICE="wlan0"
SKIP_UI_BUILD=1   # set to 0 if you plan to build UI on the Pi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --device) DEVICE="$2"; shift 2 ;;
    --skip-ui-build) SKIP_UI_BUILD=1; shift 1 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0 ..."
  exit 1
fi
if [[ -z "$REPO" ]]; then
  echo "--repo required (e.g., https://github.com/you/wids.git)"
  exit 1
fi

echo "[1/8] Apt deps"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3-venv python3-pip sqlite3 git tcpdump tshark iw net-tools ca-certificates

echo "[2/8] Create service user"
id -u wids >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d /opt/wids wids

echo "[3/8] Fetch code to /opt/wids"
mkdir -p /opt/wids
if [[ ! -d /opt/wids/.git ]]; then
  git clone --branch "$BRANCH" "$REPO" /opt/wids
else
  git -C /opt/wids fetch origin "$BRANCH"
  git -C /opt/wids checkout "$BRANCH"
  git -C /opt/wids reset --hard "origin/$BRANCH"
fi

echo "[4/8] Python venv + install"
cd /opt/wids
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip wheel
pip install -e .

echo "[5/8] Config + data"
mkdir -p /opt/wids/configs /opt/wids/data /opt/wids/logs
if [[ -f configs/wids.example.yaml && ! -f configs/wids.yaml ]]; then
  cp configs/wids.example.yaml configs/wids.yaml
fi
sed -i "s|api_key:.*|api_key: \"$API_KEY\"|g" configs/wids.yaml
sed -i "s|path: \".*db.sqlite\"|path: \"/opt/wids/data/db.sqlite\"|g" configs/wids.yaml

echo "[6/8] UI (optional)"
if [[ $SKIP_UI_BUILD -eq 0 && -d ui ]]; then
  if ! command -v npm >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
  fi
  pushd ui >/dev/null
  npm install
  npm run build
  popd >/dev/null
fi

echo "[7/8] Systemd"
install -o root -g root -m 0644 systemd/wids-sensor.service /etc/systemd/system/
install -o root -g root -m 0644 systemd/wids-api.service    /etc/systemd/system/
systemctl daemon-reload
systemctl enable wids-sensor wids-api

echo "[8/8] Permissions & helper"
chown -R wids:wids /opt/wids
setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)" || true

cat >/usr/local/bin/wids-monitor-up <<EOF
#!/usr/bin/env bash
set -e
DEV="\${1:-$DEVICE}"
ip link set "\$DEV" down
iw dev "\$DEV" set type monitor
ip link set "\$DEV" up
echo "[ok] \$DEV in monitor mode"
EOF
chmod +x /usr/local/bin/wids-monitor-up

echo
echo "Install complete."
echo "1) Put NIC in monitor mode:   sudo wids-monitor-up $DEVICE"
echo "2) Start services:            sudo systemctl start wids-sensor wids-api"
echo "3) Autostart on boot:         systemctl is-enabled wids-sensor wids-api"
echo "4) Dashboard/API:             http://<PI_IP>:8080/"
