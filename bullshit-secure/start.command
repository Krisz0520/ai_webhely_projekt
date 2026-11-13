#!/bin/sh
cd "$(dirname "$0")" || exit 1
if ! command -v node >/dev/null 2>&1; then
  echo "A Node.js nincs telepitve. Telepitsd az LTS verziot: https://nodejs.org"
  (command -v open >/dev/null 2>&1 && open https://nodejs.org) || (command -v xdg-open >/dev/null 2>&1 && xdg-open https://nodejs.org)
  printf "Nyomj Entert a kilepeshez..."; read _; exit 1
fi
URL=http://localhost:3000
[ -f certs/cert.pem ] && URL=https://localhost:8443
( sleep 2; (command -v open >/dev/null 2>&1 && open "$URL") || (command -v xdg-open >/dev/null 2>&1 && xdg-open "$URL") ) >/dev/null 2>&1 &
echo "Fut: $URL   (leallitas: Ctrl+C)"
exec node server.js
