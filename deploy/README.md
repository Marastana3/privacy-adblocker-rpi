# Deployment

Two ways to run the ad-blocker on the Raspberry Pi. Both run the DNS resolver
and dashboard API together (`run.py`).

## Option A — Docker (recommended)

```bash
# set privacy.db_path: "/data/adblocker.db" in config.yaml first
docker compose up -d --build
# with an API key protecting write endpoints:
PAB_API_KEY=your-secret docker compose up -d --build
```

Uses host networking so the DNS server serves the LAN on port 53. The dashboard
is at `http://<pi-ip>:8000`.

## Option B — systemd

```bash
sudo useradd --system --no-create-home adblocker
sudo mkdir -p /opt/privacy-adblocker-rpi
sudo rsync -a --exclude .venv --exclude node_modules ./ /opt/privacy-adblocker-rpi/
cd /opt/privacy-adblocker-rpi
sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements.txt
(cd frontend && npm install && npm run build)   # optional: dashboard at /

sudo cp deploy/adblocker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now adblocker
sudo systemctl status adblocker
```

## Freeing port 53

Raspberry Pi OS often runs `systemd-resolved` on port 53. Free it first:

```bash
sudo systemctl disable --now systemd-resolved
# set a working resolver for the Pi itself:
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
```

Then set `dns.listen_port: 53` in `config.yaml`.

## Verify

```bash
dig @<pi-ip> doubleclick.net     # -> 0.0.0.0 (blocked)
dig @<pi-ip> example.com         # -> real address (forwarded)
python scripts/evaluate.py --host <pi-ip> --port 53
```
