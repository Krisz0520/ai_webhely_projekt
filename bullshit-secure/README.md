# Bullshit-elemzés – biztonságos, kétnyelvű webalkalmazás

Többoldalas, Apple-stílusú weboldal a „bullshit” (süket duma) elemzéséről, belépéssel, titkosított adattárolással, kétlépcsős azonosítással, sötét/világos móddal és magyar/angol nyelvvel.

**Nincs külső függőség**: csak a Node.js kell hozzá (18-as vagy újabb verzió), semmit nem kell telepíteni (`npm install` nem szükséges).

## Legegyszerűbb indítás (dupla kattintás)

- **Windows:** kattints duplán a `start.bat` fájlra.
- **Mac:** kattints duplán a `start.command` fájlra (első alkalommal: jobb klikk, Megnyitás).
- **Linux:** `sh start.command`

A fájl elindítja a szervert, és megnyitja a böngészőben az oldalt. Ha a Node.js hiányzik, megnyitja a letöltőoldalát. Leállítás: zárd be az ablakot, vagy nyomj Ctrl+C-t.

## Indítás parancssorból

```bash
cd bullshit-secure
npm start
```

Ezután nyisd meg: **http://localhost:3000**. Regisztrálj egy fiókot, és belépés után elérhető az összes oldal.

### HTTPS bekapcsolása (ajánlott)

```bash
npm run cert     # önaláírt tanúsítványt készít a certs/ mappába (OpenSSL kell hozzá)
npm start        # innentől https://localhost:8443
```

A böngésző egyszer figyelmeztet az önaláírt tanúsítványra, ez helyi használatnál várt. Nyilvános üzemhez használj valódi tanúsítványt: másold a `key.pem` és `cert.pem` fájlokat a `certs/` mappába, vagy tedd a szervert TLS-t kezelő fordított proxy (például Caddy vagy nginx) mögé.

## Ubuntu szerveren (telepítés egy paranccsal)

Ubuntu vagy Debian szerveren a `deploy/install.sh` mindent beállít: Node.js 24 LTS, külön rendszerfelhasználó, automatikusan induló és újraindító szolgáltatás (szigorított systemd beállításokkal), a titkosítási jelmondat generálása és HTTPS.

**1. Másold fel és csomagold ki a szerveren:**

```bash
scp bullshit-secure.zip felhasznalo@szerver:~
ssh felhasznalo@szerver
sudo apt install -y unzip && unzip bullshit-secure.zip && cd bullshit-secure
```

**2. Telepítés, a két lehetőség közül az egyik:**

```bash
sudo sh deploy/install.sh pelda.hu    # saját tartománnyal: valódi HTTPS (Caddy + Let's Encrypt)
sudo sh deploy/install.sh             # tartomány nélkül: önaláírt HTTPS, https://SZERVER-IP:8443
```

Tartományhoz a tartomány A rekordjának a szerver IP-címére kell mutatnia, és a 80 és 443 portnak elérhetőnek kell lennie kívülről (felhő-szolgáltatónál a biztonsági csoportban is). A szkript végén kiírja az oldal címét.

**Kezelés:**

```bash
sudo systemctl status bullshit       # állapot
sudo journalctl -u bullshit -f       # napló
sudo bullshit-admin list             # felhasználók
sudo bullshit-admin create <név>     # új felhasználó (ideiglenes jelszót ír ki)
sudo bullshit-admin reset-password <név>
```

**Frissítés:** másold fel az új verziót, és futtasd újra ugyanazt a telepítőparancsot. A felhasználók és a titkosítási kulcs megmaradnak.

**Nyilvános szerveren** érdemes letiltani az önregisztrációt, és a felhasználókat a `bullshit-admin create` paranccsal létrehozni:

```bash
echo ALLOW_REGISTRATION=false | sudo tee -a /etc/bullshit.env && sudo systemctl restart bullshit
```

**Mit hova tesz:** program: `/opt/bullshit`, adatok: `/var/lib/bullshit`, beállítások és a titkosítási jelmondat: `/etc/bullshit.env` (csak root olvashatja). **Ezt a kettőt mentsd rendszeresen**, nélkülük az adatok nem olvashatók vissza.

Az IP-címes (tartomány nélküli) mód önaláírt tanúsítványt használ, ezért a böngésző egyszer figyelmeztet. Ha a szerver IP-címe változik, töröld a `/var/lib/bullshit/certs` mappát, és futtasd újra a telepítőt.

## Oldalak

| Útvonal | Tartalom | Interaktív elem |
|---|---|---|
| `/login` | Belépés, regisztráció, 2FA-lépés | Jelszóerősség-mérő, jelszó mutatása |
| `/` | Kezdőlap | Bullshit-generátor, haladás-kártya (gyűrű) |
| `/frankfurt` | Frankfurt elmélete | Szerepkísérlet (csúszka és kapcsoló) |
| `/types` | A bullshit fajtái | Szűrő, lenyitható példák, animált skálák |
| `/detector` | Bullshit-detektor | Élő elemzés beillesztett szövegen |
| `/quiz` | Kvíz (8 kérdés) | Pontszám, legjobb eredmény mentése |
| `/workplace` | Céges bullshit | Bullshit-bingó, gépelő animáció |
| `/defense` | Védekezés | Mentett ellenőrzőlista, Brandolini-szemléltetés |
| `/account` | Fiók és biztonság | 2FA, jelszócsere, munkamenetek, napló, fióktörlés |

A felső sávban váltható a nyelv (HU/EN) és a téma (automatikus, világos, sötét). Alapértelmezetten a böngésző nyelve és a rendszer témája érvényesül.

## Biztonság

| Terület | Megoldás |
|---|---|
| Jelszavak | scrypt (N=32768), egyedi 16 bájtos só, időzítés-biztos összehasonlítás. A jelszót magát soha nem tároljuk. |
| Jelszó-szabályok | Legalább 10 karakter, tiltott gyakori jelszavak és a felhasználónévvel egyező jelszó. |
| Adattárolás | A teljes felhasználói adatbázis **AES-256-GCM** titkosítású (`data/users.enc`). Módosítás esetén a szerver nem indul el. A fájl 0600 jogosultságú, az írás atomi. |
| Kulcs | Véletlen 32 bájtos kulcs (`data/secret.key`), vagy az `APP_SECRET` környezeti változóból scrypt-tel képzett kulcs. |
| Kétlépcsős azonosítás | TOTP (RFC 6238), bármely hitelesítő alkalmazással. Egy kód nem használható fel kétszer. |
| Munkamenetek | 256 bites véletlen azonosító; a szerver csak a SHA-256 lenyomatát tartja. `HttpOnly`, `SameSite=Strict`, HTTPS-en `Secure` és `__Host-` előtagú süti. 30 perc inaktivitás vagy 8 óra után lejár. Belépéskor új azonosítót kap (session fixation ellen). |
| CSRF | Egyedi token minden módosító kérésen, plusz `Origin` és `Sec-Fetch-Site` ellenőrzés. |
| Brute force ellen | Korlátozás IP-re, IP+felhasználóra és felhasználóra; külön a 2FA-ra, a regisztrációra és az újrahitelesítésre. A nem létező felhasználónál is ugyanannyi ideig tart a válasz. |
| Fejlécek | Szigorú CSP (`default-src 'none'`, nincs inline szkript vagy stílus), HSTS (HTTPS-en), `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP. |
| Szerver | Csak engedélyezőlistán szereplő fájlok szolgálhatók ki; Host-fejléc ellenőrzés (DNS-rebinding ellen); kérésméret- és időkorlátok; nyilvános címen HTTPS nélkül nem indul el. |
| Érzékeny műveletek | Jelszócsere, 2FA kikapcsolása és fióktörlés újra kéri a jelszót (és 2FA mellett a kódot). Jelszócsere után a többi eszközről kijelentkeztet. |
| Napló | Az utolsó 10 biztonsági esemény megtekinthető a Fiók oldalon. |

A `npm test` 97 ellenőrzést futtat: hitelesítés, CSRF, korlátozás, 2FA (köztük az RFC 6238 tesztvektora), titkosítás, a módosítás észlelése, HTTPS-süti, fordítások azonosságát.

## Beállítások (környezeti változók)

| Változó | Jelentés | Alapérték |
|---|---|---|
| `PORT` | Port | 3000 (HTTPS-nél 8443) |
| `HOST` | Figyelt cím | 127.0.0.1 |
| `APP_SECRET` | Jelmondat az adatfájl kulcsához (a kulcsfájl helyett) | nincs |
| `ALLOW_REGISTRATION` | `false` esetén új fiók nem hozható létre | true |
| `MAX_USERS` | Fiókok maximális száma | 500 |
| `ALLOWED_HOSTS` | Vesszővel elválasztott engedélyezett hostnevek (nyilvános üzemhez) | csak localhost |
| `TRUST_PROXY` | `1`: a kliens IP-je az `X-Forwarded-For` utolsó eleme (csak megbízható proxy mögött!) | 0 |
| `COOKIE_SECURE` | `1`: Secure sütik, ha a TLS-t a proxy végzi | 0 |
| `DATA_DIR`, `CERT_DIR` | Adat- és tanúsítvány-mappa | `./data`, `./certs` |

Példa nyilvános üzemhez, fordított proxy mögött:

```bash
HOST=127.0.0.1 PORT=3000 TRUST_PROXY=1 COOKIE_SECURE=1 ALLOWED_HOSTS=pelda.hu \
APP_SECRET='hosszú-egyedi-jelmondat' ALLOW_REGISTRATION=false npm start
```

## Felhasználók kezelése

Állítsd le a szervert, majd:

```bash
node admin.js list                    # felhasználók listája
node admin.js create <név>            # új felhasználó (ideiglenes jelszót ír ki)
node admin.js reset-password <név>    # ideiglenes jelszó (elfelejtett jelszóhoz)
node admin.js disable-2fa <név>       # 2FA kikapcsolása (elveszett telefonhoz)
node admin.js delete <név>            # felhasználó törlése
```

## Fájlok

- `server.js`: HTTP(S) szerver, API, biztonsági fejlécek
- `auth.js`: jelszókezelés, munkamenetek, korlátozók
- `store.js`: titkosított adattár
- `totp.js`: kétlépcsős azonosítás
- `deploy/install.sh`: Ubuntu/Debian szerver-telepítő
- `start.bat`, `start.command`: dupla kattintásos indítók
- `admin.js`, `gen-cert.sh`, `test.js`: kezelő eszközök és tesztek
- `layout.html`, `*.html`: oldalsablonok
- `style.css`, `app.js`, `login.js`, `theme.js`: megjelenés és működés
- `hu.json`, `en.json`: fordítások (új nyelv: új JSON-fájl és a `LANGS` lista a `server.js`-ben)

## Fontos tudnivalók

- **Mentsd a `data/` mappát.** Az adatfájl a kulcs nélkül olvashatatlan, tehát a `data/secret.key` (vagy az `APP_SECRET`) elvesztése a fiókok végleges elvesztését jelenti. A kulcsot tárold az adatfájltól elkülönítve is.
- **A munkamenetek memóriában vannak**, ezért a szerver újraindítása mindenkit kijelentkeztet. A fiókok megmaradnak.
- **Nincs e-mailes jelszó-visszaállítás**, mert nincs e-mail-küldés. Ezt az `admin.js` pótolja.
- **A korlátozások a szerver memóriájában élnek**, így újraindításkor nullázódnak. Több példányos üzemhez közös tárolóra (például Redisre) kellene cserélni.
- A fájlalapú adattár néhány száz felhasználóig megfelelő; nagyobb terheléshez adatbázis kell.
- Ez egy gondosan megépített, tesztelt alkalmazás, de független biztonsági felülvizsgálat (penetrációs teszt) nélkül ne kezeld ellenőrzött védelemként érzékeny, valós adatoknál.

## Források

Harry G. Frankfurt: *On Bullshit* (1986/2005); Pennycook és mások (2015): pseudo-profound bullshit kutatás; David Graeber: *Bullshit Jobs* (2018). A szövegek saját megfogalmazások.
