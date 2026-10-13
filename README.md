# Proton AmneziaWG Studio v5.1 (Anti-Censorship Edition)

An automated desktop application built with **Python & Flet** designed for users in heavily restricted and filtered network environments (such as Iran) to discover, test, and generate **AmneziaWG** (obfuscated WireGuard) configurations for Proton VPN.

---

## 🌟 Key Features

1. **Proton Infrastructure & Server Harvester**:
   - Downloads and maintains the full database of Proton VPN servers across global locations (Free and Plus tiers).
   - Extracts server public keys, IP addresses, exit capabilities, and features (P2P, Tor, Secure Core).
   - Built-in Playwright automated browser module to sync credentials and configs from the Proton web dashboard.

2. **Censorship & DPI Bypass (AmneziaWG)**:
   - Injects tested protocol obfuscation parameters (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`-`H4`) into WireGuard profiles to defeat Deep Packet Inspection (DPI) filtering on ports `51820`, `443`, and custom UDP ports.
   - Replaces poisoned DNS hostnames with verified direct IPs.

3. **Multi-Threaded DNS & UDP Reachability Engine**:
   - Queries Google, Cloudflare, and Quad9 DoH to discover unblocked IPs.
   - Concurrent UDP probing to measure live round-trip latency and packet response.
   - Visual latency badges (`🟢 Fast`, `🟡 Medium`, `🔴 Slow`).

4. **Batch Exporter**:
   - Export all verified configs grouped into continent/country folders as ZIP archives or direct `.conf` files.
   - Generates Shadowrocket, AmneziaVPN, and WireGuard-compatible profiles.

5. **VPN Pre-Flight Detection**:
   - Automatically detects active system VPN tunnels before running network scans to prevent false-positive reachability results.

---

## 🚀 Quick Start

```bash
git clone https://github.com/Behrouz64/Proton-AmneziaWG-Studio.git
cd Proton-AmneziaWG-Studio
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

---

## 🧪 Automated Tests

```bash
pytest tests -v
```

---

## 📄 License

MIT License. Developed for research and educational network freedom purposes.
