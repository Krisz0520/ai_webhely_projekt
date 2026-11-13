#!/bin/sh
# Ubuntu / Debian telepítő. Többször futtatható: frissítéskor is ezt használd.
#
#   sudo sh deploy/install.sh pelda.hu    HTTPS valódi tanúsítvánnyal (Caddy + Let's Encrypt)
#                                         Előfeltétel: a tartomány A rekordja a szerverre mutat,
#                                         és a 80 és 443 port elérhető kívülről.
#   sudo sh deploy/install.sh             Tartomány nélkül: önaláírt HTTPS a 8443 porton, IP-címen.
#
# Mit csinál: Node.js 24 LTS, külön rendszerfelhasználó, systemd szolgáltatás (szigorított),
# titkosítási jelmondat generálása, HTTPS beállítása, tűzfalszabály (ha az ufw aktív).
set -eu

T="${TEST_MODE:-0}"                       # 1 = csak a fájlokat állítja elő (a szkript tesztjéhez)
APP="${APP:-/opt/bullshit}"
DATA="${DATA:-/var/lib/bullshit}"
ENVF="${ENVF:-/etc/bullshit.env}"
UNIT="${UNIT:-/etc/systemd/system/bullshit.service}"
CADDY_DIR="${CADDY_DIR:-/etc/caddy}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DOMAIN="${1:-}"
export DEBIAN_FRONTEND=noninteractive

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nHIBA: %s\n' "$*" >&2; exit 1; }

if [ "$T" != 1 ]; then
  [ "$(id -u)" -eq 0 ] || die "Futtasd sudo-val:  sudo sh $0 [tartomány]"
  command -v apt-get >/dev/null 2>&1 || die "Ez a szkript Ubuntu/Debian rendszerre készült."
fi

if [ -n "$DOMAIN" ]; then
  case "$DOMAIN" in
    *[!a-zA-Z0-9.-]*|-*|.*|*..*) die "Érvénytelen tartománynév: $DOMAIN" ;;
    *.*) : ;;
    *) die "A tartománynévnek tartalmaznia kell egy pontot (például pelda.hu)." ;;
  esac
  case "$DOMAIN" in
    *[!0-9.]*) : ;;
    *) die "IP-cím esetén hagyd el a paramétert: sudo sh $0" ;;
  esac
fi

[ -f "$SRC/server.js" ] || die "Nem találom a server.js fájlt. Futtasd a projekt mappájából: sudo sh deploy/install.sh"

# ----------------------------------------------------------------- csomagok és Node
if [ "$T" != 1 ]; then
  say "Alapcsomagok"
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates gpg openssl

  NODE_OK=0
  if command -v node >/dev/null 2>&1; then
    [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 20 ] && NODE_OK=1
  fi
  if [ "$NODE_OK" -ne 1 ]; then
    say "Node.js 24 LTS telepítése (NodeSource)"
    install -m 0755 -d /usr/share/keyrings
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor --batch --yes -o /usr/share/keyrings/nodesource.gpg
    chmod 644 /usr/share/keyrings/nodesource.gpg
    cat > /etc/apt/sources.list.d/nodesource.sources <<EOF
Types: deb
URIs: https://deb.nodesource.com/node_24.x
Suites: nodistro
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: /usr/share/keyrings/nodesource.gpg
EOF
    apt-get update -qq
    apt-get install -y -qq nodejs
  fi
fi
NODE_BIN="$(command -v node || echo /usr/bin/node)"

# ----------------------------------------------------------- felhasználó és fájlok
say "Alkalmazás telepítése ide: $APP"
if [ "$T" != 1 ]; then
  id bullshit >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin bullshit
fi
mkdir -p "$APP" "$DATA"
tar -C "$SRC" --exclude=./data --exclude=./certs --exclude=./deploy --exclude=./node_modules \
    --exclude=./test.js --exclude=./start.bat --exclude=./start.command -cf - . | tar -C "$APP" -xf -
chmod -R go-w,a+rX "$APP"
chmod 700 "$DATA"
if [ "$T" != 1 ]; then
  chown -R root:root "$APP"
  chown bullshit:bullshit "$DATA"
fi

# ------------------------------------------------------------------ beállítófájl
# A titkosítási jelmondat (APP_SECRET) csak egyszer jön létre. Ha elveszik, az adatok nem olvashatók.
say "Beállítások: $ENVF"
set_env() {
  if grep -q "^$1=" "$ENVF" 2>/dev/null; then
    sed -i "s|^$1=.*|$1=$2|" "$ENVF"
  else
    echo "$1=$2" >> "$ENVF"
  fi
}
del_env() { [ -f "$ENVF" ] && sed -i "/^$1=/d" "$ENVF" || true; }

( umask 077; touch "$ENVF" )
chmod 600 "$ENVF"
grep -q '^APP_SECRET=' "$ENVF" || echo "APP_SECRET=$(openssl rand -hex 32)" >> "$ENVF"
set_env DATA_DIR "$DATA"
set_env NODE_ENV production

if [ -n "$DOMAIN" ]; then
  MODE=domain
  set_env HOST 127.0.0.1
  set_env PORT 3000
  set_env TRUST_PROXY 1
  set_env COOKIE_SECURE 1
  set_env ALLOWED_HOSTS "$DOMAIN"
  del_env CERT_DIR
  URL="https://$DOMAIN"
else
  MODE=ip
  IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
  [ -n "$IPS" ] || IPS=127.0.0.1
  HOSTS="$(echo "$IPS" | paste -sd, -)"
  CERTS="$DATA/certs"
  if [ ! -f "$CERTS/cert.pem" ]; then
    say "Önaláírt tanúsítvány készítése"
    mkdir -p "$CERTS"
    SAN="DNS:localhost,IP:127.0.0.1"
    for ip in $IPS; do SAN="$SAN,IP:$ip"; done
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "$CERTS/key.pem" -out "$CERTS/cert.pem" -days 825 \
      -subj "/CN=bullshit" -addext "subjectAltName=$SAN" 2>/dev/null
    chmod 600 "$CERTS/key.pem"
    [ "$T" = 1 ] || chown -R bullshit:bullshit "$CERTS"
  fi
  set_env HOST 0.0.0.0
  set_env PORT 8443
  set_env TRUST_PROXY 0
  set_env COOKIE_SECURE 1
  set_env ALLOWED_HOSTS "$HOSTS"
  set_env CERT_DIR "$CERTS"
  URL="https://$(echo "$IPS" | head -n1):8443"
fi

# --------------------------------------------------------------------- szolgáltatás
say "Rendszerszolgáltatás"
mkdir -p "$(dirname "$UNIT")"
cat > "$UNIT" <<EOF
[Unit]
Description=Bullshit-elemzés
After=network-online.target
Wants=network-online.target

[Service]
User=bullshit
Group=bullshit
WorkingDirectory=$APP
EnvironmentFile=$ENVF
ExecStart=$NODE_BIN server.js
Restart=always
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
EOF

# Kezelőparancs: leállítja a szolgáltatást, lefuttatja az admin.js-t, majd újraindítja.
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/bullshit-admin" <<EOF
#!/bin/sh
# Használat: sudo bullshit-admin list | create <név> | reset-password <név> | disable-2fa <név> | delete <név>
set -a; . "$ENVF"; set +a
systemctl stop bullshit
runuser -u bullshit -- env DATA_DIR="\$DATA_DIR" APP_SECRET="\$APP_SECRET" "$NODE_BIN" "$APP/admin.js" "\$@"
rc=\$?
systemctl start bullshit
exit \$rc
EOF
chmod 755 "$BIN_DIR/bullshit-admin"

if [ "$T" != 1 ]; then
  systemctl daemon-reload
  systemctl enable bullshit >/dev/null 2>&1
  systemctl restart bullshit
fi

# ------------------------------------------------------------------------- Caddy
if [ "$MODE" = domain ]; then
  if [ "$T" != 1 ] && ! command -v caddy >/dev/null 2>&1; then
    say "Caddy telepítése (automatikus HTTPS)"
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --batch --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
  fi
  say "Caddy beállítása: $DOMAIN"
  mkdir -p "$CADDY_DIR/conf.d"
  cat > "$CADDY_DIR/conf.d/bullshit.caddy" <<EOF
$DOMAIN {
	encode gzip zstd
	reverse_proxy 127.0.0.1:3000
}
EOF
  grep -qs 'conf.d' "$CADDY_DIR/Caddyfile" || echo "import $CADDY_DIR/conf.d/*.caddy" >> "$CADDY_DIR/Caddyfile"
  [ "$T" = 1 ] || systemctl reload caddy 2>/dev/null || systemctl restart caddy
fi

# ------------------------------------------------------------------------ tűzfal
if [ "$T" != 1 ] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  say "Tűzfal (ufw)"
  if [ "$MODE" = domain ]; then ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
  else ufw allow 8443/tcp >/dev/null; fi
fi

# ------------------------------------------------------------------- ellenőrzés
if [ "$T" != 1 ]; then
  say "Ellenőrzés"
  if [ "$MODE" = domain ]; then CHECK="http://127.0.0.1:3000/login"; else CHECK="-k https://127.0.0.1:8443/login"; fi
  OK=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -s -o /dev/null -w '%{http_code}' $CHECK 2>/dev/null | grep -q 200; then OK=1; break; fi
    sleep 1
  done
  if [ "$OK" -ne 1 ]; then
    journalctl -u bullshit -n 30 --no-pager || true
    die "A szolgáltatás nem válaszol. A fenti napló segít a hiba megtalálásában."
  fi
fi

cat <<EOF

KÉSZ. Az oldal itt érhető el:  $URL
EOF
if [ "$MODE" = ip ]; then
  echo "A böngésző egyszer figyelmeztet az önaláírt tanúsítványra (ez várt). Valódi tanúsítványhoz használj tartományt:  sudo sh deploy/install.sh pelda.hu"
else
  echo "Ha az oldal nem nyílik meg: ellenőrizd, hogy $DOMAIN a szerver IP-címére mutat, és a 80 és 443 port nyitva van."
fi
cat <<EOF

Hasznos parancsok:
  sudo systemctl status bullshit          állapot
  sudo journalctl -u bullshit -f          napló
  sudo bullshit-admin list                felhasználók
  sudo bullshit-admin create <név>        új felhasználó (ideiglenes jelszót ír ki)

Új regisztrációk tiltása (ha csak általad létrehozott felhasználók léphetnek be):
  sudo sed -i 's/^ALLOW_REGISTRATION=.*//' $ENVF && echo ALLOW_REGISTRATION=false | sudo tee -a $ENVF && sudo systemctl restart bullshit

MENTSD (nélkülük az adatok olvashatatlanok):  $ENVF   és   $DATA
Frissítés: másold fel az új verziót, majd futtasd újra ugyanezt a parancsot.
EOF
