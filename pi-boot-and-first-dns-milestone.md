# Milestone 1 — Pi Boot + First DNS Resolver

Goal: boot the headless Pi, reach it over SSH from your Mac, deploy the resolver code, run it on port 53, and prove it actually blocks a tracker domain from another device on your network.

Target: one clean end-to-end path. Every box below is either "type this" or "confirm this." Check them off in order — later steps assume the earlier ones passed.

---

## Phase A — Boot & first contact

- [ ] **Insert the flashed SD card** into the Pi, connect power, wait ~60–90s for first boot (it expands the filesystem and joins WiFi).
- [ ] **From your Mac, confirm the Pi is on the network:**
  ```bash
  ping adblocker.local
  ```
  You want replies. `Ctrl+C` to stop.
- [ ] **SSH in** (replace `mara` with the username you set in the Imager):
  ```bash
  ssh mara@adblocker.local
  ```
  Type `yes` at the fingerprint prompt the first time, then your password. A shell prompt on the Pi = success.

**If `adblocker.local` doesn't resolve** (mDNS not working on your network):
- [ ] Find the Pi's IP from your router's admin page (look for hostname `adblocker`), or:
  ```bash
  ping adblocker.local        # sometimes still prints the IP even if ssh name-lookup fails
  ```
- [ ] SSH by IP instead: `ssh mara@192.168.x.x`

---

## Phase B — Secure & update (do once)

- [ ] **Update the OS:**
  ```bash
  sudo apt update && sudo apt full-upgrade -y
  ```
- [ ] **Set up SSH keys** so you stop typing the password. Run this **on your Mac**, not the Pi:
  ```bash
  ssh-copy-id mara@adblocker.local
  ```
  Then re-run `ssh mara@adblocker.local` — it should log in with no password.
- [ ] **Reboot to apply kernel/firmware updates:**
  ```bash
  sudo reboot
  ```
  Wait a minute, then SSH back in.

---

## Phase C — Dev environment (VSCode Remote-SSH)

- [ ] In VSCode on your Mac, install the **Remote - SSH** extension (if not already).
- [ ] `Cmd+Shift+P` → **Remote-SSH: Connect to Host** → `mara@adblocker.local`.
- [ ] Once connected, **Open Folder** → your home dir on the Pi. You can now edit files on the Pi directly.
- [ ] Confirm Python 3 is present:
  ```bash
  python3 --version
  ```

---

## Phase D — Get the code onto the Pi

- [ ] **Clone your repo** on the Pi:
  ```bash
  cd ~
  git clone https://github.com/Marastana3/privacy-adblocker-rpi.git
  cd privacy-adblocker-rpi
  ```
- [ ] Make sure the **six bug fixes and the corrected `resolver.py` are committed** to `main` first (push them from wherever they currently live), so the clone actually contains them. Then `git pull` on the Pi to be current.
- [ ] **Create a virtual environment** and install dependencies:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt   # or: pip install dnslib  (if no requirements file yet)
  ```

---

## Phase E — Free up port 53

Raspberry Pi OS often runs `systemd-resolved`, which already listens on port 53 and will block your resolver from binding.

- [ ] **Check what's on port 53:**
  ```bash
  sudo ss -tulpn | grep :53
  ```
- [ ] If `systemd-resolved` is holding it, stop it so your resolver can bind:
  ```bash
  sudo systemctl stop systemd-resolved
  ```
  (For now this is fine for testing. We'll make this permanent and set an upstream resolver properly in a later milestone.)

---

## Phase F — Run the resolver

- [ ] **Start it** (ports below 1024 need root, hence `sudo`; use the venv's python):
  ```bash
  sudo .venv/bin/python resolver.py
  ```
- [ ] It should print that it's listening on `0.0.0.0:53` (or similar) with no traceback. Leave it running in this terminal.
- [ ] **From a second SSH session on the Pi**, test a query against itself:
  ```bash
  dig @127.0.0.1 example.com          # a normal domain → should resolve to a real IP
  dig @127.0.0.1 doubleclick.net      # a tracker on your blocklist → should return 0.0.0.0 / NXDOMAIN
  ```
  Install `dig` if missing: `sudo apt install dnsutils -y`.

**This is the core milestone check:** a normal domain resolves, a blocklisted domain is nulled. If both behave correctly, the resolver works.

---

## Phase G — Prove it on a real device

- [ ] On your **Mac** (or phone), set DNS to the Pi's address:
  - Mac: System Settings → Network → your WiFi → Details → DNS → add the Pi's IP (e.g. `192.168.x.x`), remove the others temporarily.
- [ ] Flush the Mac DNS cache:
  ```bash
  sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
  ```
- [ ] Browse a site with ads/trackers and confirm known tracker domains fail to resolve while normal sites load. Watch the resolver's terminal on the Pi — you should see the queries streaming in.
- [ ] **Restore your Mac's DNS** when done testing so you're not dependent on the Pi being up.

---

## Milestone complete when

You can point a client at the Pi, load a normal website, and see at least one tracker/ad domain blocked — with the queries visible in the resolver log. That's your first working end-to-end privacy ad-blocker.

---

## Quick troubleshooting

- **`ssh: Could not resolve hostname adblocker.local`** → mDNS issue; use the IP address (Phase A fallback).
- **`Permission denied (publickey,password)`** → wrong username; it's the one you set in the Imager, not `pi` by default.
- **`Address already in use` on port 53** → something still bound to 53; re-run Phase E, `sudo ss -tulpn | grep :53`.
- **Resolver starts but `dig` times out** → check the Pi's firewall isn't blocking UDP 53, and that you ran with `sudo` (needed to bind 53).
- **Blocklist domain still resolves** → the blocklist isn't being loaded/applied; this is the "privacy mode logic not connected" bug — confirm that fix is actually in the running `resolver.py`.

---

## Right after this milestone

- Make port-53 handling permanent (disable `systemd-resolved`'s stub listener, set a real upstream like `1.1.1.1`).
- Run the resolver as a `systemd` service so it survives reboots and starts on boot.
- Then move on to the privacy layer (anonymizer → aggregator → retention policies).
