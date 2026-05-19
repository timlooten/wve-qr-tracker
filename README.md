# wve-qr-tracker

QR-code tracker voor W.V.E. B.V. — genereert trackbare QR-codes en registreert iedere scan met locatie, apparaat en browserdata.

Draait op Berry op poort `5010`, bereikbaar via `https://qr.wve.nl`.

## Wat doet het

- Maak campagne-QR-codes aan die doorsturen naar een doelURL
- Elke scan wordt gelogd: IP, land, stad, ISP, apparaat, OS, browser, taal en referrer
- Admin dashboard met scanhistorie, statistieken en CSV-export
- QR-codes zijn aan/uit te zetten zonder de link te breken

## Stack

| Component | Technologie |
|-----------|------------|
| Backend | Python / Flask |
| Database | SQLite (`qr_tracker.db`) |
| QR generatie | `qrcode[pil]` + Pillow |
| Geo lookup | ipapi.co (gratis tier) |
| Hosting | Berry (Mac mini), systemd service |

## Installatie op Berry

```bash
./deploy_berry.sh
```

Dit script kopieert de bestanden, installeert dependencies in een venv, en installeert + start de systemd service.

Pas daarna het wachtwoord aan in de service-definitie:

```bash
sudo nano /etc/systemd/system/qr_tracker.service
# Zet QR_ADMIN_PASSWORD op iets veiligs
sudo systemctl daemon-reload && sudo systemctl restart qr_tracker
```

## Configuratie (omgevingsvariabelen)

| Variabele | Standaard | Omschrijving |
|-----------|-----------|--------------|
| `QR_BASE_URL` | `https://qr.wve.nl` | Publieke basis-URL voor QR-links |
| `QR_ADMIN_PASSWORD` | `changeme` | Wachtwoord admin dashboard |
| `QR_DB_PATH` | `~/qr_tracker.db` | Pad naar SQLite database |
| `QR_PORT` | `5010` | Poort waarop de app luistert |
| `QR_SECRET_KEY` | random | Flask session secret (stel in voor stabiliteit) |

## Lokaal testen

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
QR_ADMIN_PASSWORD=test python qr_app.py
# Open http://localhost:5010/admin
```

## Beheer

```bash
# Status
ssh berry sudo systemctl status qr_tracker

# Logs
ssh berry sudo journalctl -u qr_tracker -f

# Restart
ssh berry sudo systemctl restart qr_tracker
```

## Bestanden

| Bestand | Doel |
|---------|------|
| `qr_app.py` | Flask applicatie (routes, database, admin UI) |
| `requirements.txt` | Python dependencies |
| `qr_tracker.service` | systemd service definitie |
| `deploy_berry.sh` | Deploy-script naar Berry |
