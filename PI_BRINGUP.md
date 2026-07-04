# Raspberry Pi Bring-Up Day — Runbook

One ordered pass from a fresh Pi to a working, measured ad-blocker on your LAN.
Each phase ends in a check you can verify before moving on. Budget ~2 hours the
first time.

Related docs: `pi-boot-and-first-dns-milestone.md` (boot detail), `deploy/README.md`
(deploy detail), `README.md` (config), `ROADMAP.md` (where this fits).

---

## Phase 1 — Boot & reach the Pi  (~20 min)

- [ ] Flash Raspberry Pi OS Lite (64-bit) with the Imager. In OS Customisation set:
      hostname `adblocker`, enable SSH, your WiFi + `Europe/Bucharest`, a username.
- [ ] Insert the SD card, power on, wait ~90s.
- [ ] From your Mac: `ping adblocker.local` → replies.
- [ ] `ssh <user>@adblocker.local` → you get a shell.
      *Fallback if `.local` fails:* find the IP on your router and `ssh <user>@<ip>`.

**Check:** you are logged into the Pi over SSH.

## Phase 2 — Update & get the code on the Pi  (~20 min)

- [ ] `sudo apt update && sudo apt full-upgrade -y`
- [ ] Set up key login (run on your Mac): `ssh-copy-id <user>@adblocker.local`
- [ ] Install prerequisites: `sudo apt install -y git python3-venv python3-pip`
- [ ] Get the repo (either works):
      - `git clone https://github.com/Marastana3/privacy-adblocker-rpi.git`
      - or develop over VSCode Remote-SSH and push/pull as you go
- [ ] `cd privacy-adblocker-rpi`

**Check:** `ls` shows `dns_engine/ app/ privacy/ run.py config.yaml`.

## Phase 3 — Run it on a high port first (no root)  (~15 min)

Prove the software works before touching port 53.

- [ ] `python3 -m venv .venv && source .venv/bin/activate`
- [ ] `pip install -r requirements.txt`
- [ ] Leave `config.yaml` at `dns.listen_port: 5300` for now.
- [ ] `python -m dns_engine.resolver`  (starts the resolver)
- [ ] From a second SSH session:
      - `dig @127.0.0.1 -p 5300 doubleclick.net` → `0.0.0.0`
      - `dig @127.0.0.1 -p 5300 example.com` → a real address
- [ ] Run the tests once on the Pi: `python -m unittest discover -s tests`

**Check:** blocked domain sinkholes, normal domain resolves, tests pass.

## Phase 4 — Free port 53 and go live  (~20 min)

- [ ] See what holds port 53: `sudo ss -tulpn | grep :53`
- [ ] Disable the stub resolver:
      ```
      sudo systemctl disable --now systemd-resolved
      echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
      ```
- [ ] In `config.yaml` set `dns.listen_port: 53` and `dns.listen_host: "0.0.0.0"`.
- [ ] (Optional but recommended) set `privacy.db_path: "/data/adblocker.db"` if you
      will use Docker; otherwise leave the default.

**Check:** `sudo ss -tulpn | grep :53` shows nothing bound yet.

## Phase 5 — Install as a service  (~25 min)

Pick ONE. Both run DNS + dashboard together via `run.py`.

### Option A — Docker
- [ ] Install Docker: `curl -fsSL https://get.docker.com | sh`
- [ ] Build the dashboard is handled inside the image. Start it:
      `docker compose up -d --build`  (add `PAB_API_KEY=secret` in front to lock writes)
- [ ] `docker compose logs -f` to watch startup.

### Option B — systemd
- [ ] `sudo useradd --system --no-create-home adblocker`
- [ ] `sudo mkdir -p /opt/privacy-adblocker-rpi && sudo rsync -a --exclude .venv --exclude node_modules ./ /opt/privacy-adblocker-rpi/`
- [ ] `cd /opt/privacy-adblocker-rpi && sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements.txt`
- [ ] (optional dashboard) `cd frontend && npm install && npm run build`
- [ ] `sudo cp deploy/adblocker.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now adblocker`
- [ ] `sudo systemctl status adblocker` → active (running)

**Check:** service is running and survives `sudo reboot`.

## Phase 6 — Point a real client & confirm blocking  (~15 min)

- [ ] On your Mac: System Settings → Network → WiFi → Details → DNS → set the Pi's IP,
      remove the others temporarily. Flush cache:
      `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
- [ ] Browse normally; confirm sites load and known trackers are blocked.
- [ ] Open the dashboard at `http://<pi-ip>:8000` — watch stats climb, toggle a
      category, add a domain to the whitelist and see it take effect.
- [ ] **Restore your Mac's DNS** when done testing.

**Check:** real traffic flows through the Pi; dashboard reflects and controls it.

## Phase 7 — Capture evaluation data (thesis)  (~20 min)

- [ ] Effectiveness + latency: `python scripts/evaluate.py --host <pi-ip> --port 53 --samples 500`
- [ ] Record Pi resource use under load (second SSH session):
      `top -b -n 5 | head -20`  and  `free -h`
- [ ] For a latency baseline, compare against a public resolver:
      `dig @1.1.1.1 example.com` vs `dig @<pi-ip> example.com` (query times).
- [ ] Save the numbers — these feed the evaluation chapter.

**Check:** you have effectiveness %, latency stats, and CPU/RAM figures written down.

---

## Rollback / troubleshooting

- **Lost internet on a client:** restore its DNS to automatic/`1.1.1.1`.
- **Pi won't resolve for itself:** `echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf`.
- **Port 53 busy:** re-check `sudo ss -tulpn | grep :53`; ensure `systemd-resolved` is disabled.
- **Service won't start:** `sudo journalctl -u adblocker -e` (systemd) or `docker compose logs` (Docker).
- **Bring back the old resolver:** `sudo systemctl enable --now systemd-resolved`.
