import os
import sys
import json
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

USER_DATA_DIR = os.path.expanduser("~/.gemini/antigravity/proton_profile")
os.makedirs(USER_DATA_DIR, exist_ok=True)

OUT_FILE = "/Users/elahekaveh/Desktop/VPN antigravity/Surfshark_AmneziaWG_v5/proton_intercepted.json"

captured_data = {
    "api_calls": [],
    "servers_data": [],
    "wireguard_options": {},
    "downloads": [],
}

def save_data():
    try:
        with open(OUT_FILE, "w", encoding="utf-8") as f:
            json.dump(captured_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error saving data: {e}")

def main():
    print("=" * 60)
    print("🚀 Starting Chromium Proton VPN Dashboard Inspector...")
    print(f"📁 Profile dir: {USER_DATA_DIR}")
    print("=" * 60)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=USER_DATA_DIR,
            headless=False,
            viewport={"width": 1366, "height": 900},
            args=["--auto-open-devtools-for-tabs"],
            accept_downloads=True,
        )
        
        page = context.pages[0] if context.pages else context.new_page()

        def handle_download(download):
            try:
                sugg = download.suggested_filename
                save_path = f"/tmp/{sugg}"
                download.save_as(save_path)
                print(f"\n📥 [DOWNLOAD CAPTURED] {sugg} -> {save_path}")
                content = ""
                if os.path.exists(save_path):
                    with open(save_path, "r", errors="ignore") as f:
                        content = f.read()
                captured_data["downloads"].append({"filename": sugg, "path": save_path, "content": content})
                save_data()
            except Exception as e:
                print(f"Download error: {e}")

        page.on("download", handle_download)
        context.on("page", lambda np: np.on("download", handle_download))

        def handle_response(response):
            try:
                url = response.url
                status = response.status
                ct = response.headers.get("content-type", "")
                
                # Check for interesting proton API calls
                if "proton" in url and ("api" in url or "vpn" in url or "logical" in url or "cert" in url or "config" in url):
                    entry = {
                        "url": url,
                        "status": status,
                        "content_type": ct,
                        "time": time.time()
                    }
                    if "application/json" in ct:
                        try:
                            body = response.json()
                            entry["json"] = body
                            # Check if this JSON contains server lists
                            if isinstance(body, dict):
                                if "LogicalServers" in body or "Servers" in body:
                                    print(f"\n🎯 [FOUND SERVER LIST API] {url}")
                                    captured_data["servers_data"].append({"url": url, "data": body})
                                    save_data()
                                elif any("Endpoint" in str(v) or "PublicKey" in str(v) for v in body.values()):
                                    print(f"\n🎯 [FOUND VPN DATA API] {url}")
                                    captured_data["servers_data"].append({"url": url, "data": body})
                                    save_data()
                        except Exception:
                            pass
                    captured_data["api_calls"].append(entry)
                    save_data()
            except Exception:
                pass

        page.on("response", handle_response)

        target_url = "https://account.protonvpn.com/downloads"
        print(f"🌐 Navigating to {target_url}...")
        try:
            page.goto(target_url, wait_until="commit", timeout=45000)
        except Exception as e:
            print(f"Navigation warning: {e}")

        print("\n" + "=" * 60)
        print("👀 BROWSER IS READY!")
        print("Please log in (if needed) and explore the WireGuard section.")
        print("Switch settings (Standard / Secure Core, NetShield, NAT, Server dropdown).")
        print("The inspector is recording all network calls and DOM elements.")
        print("Press Ctrl+C in terminal when done to finish inspection.")
        print("=" * 60 + "\n")

        try:
            last_check = 0
            while True:
                time.sleep(2)
                now = time.time()
                # Inspect DOM every 5 seconds if on downloads page
                if now - last_check > 5:
                    last_check = now
                    try:
                        curr_url = page.url
                        if "downloads" in curr_url.lower():
                            # Extract visible text / options from WireGuard section
                            wg_info = page.evaluate('''() => {
                                const texts = [];
                                const elements = document.querySelectorAll('button, select, input, label, h2, h3, h4, [role="tab"], [role="switch"], [role="combobox"]');
                                elements.forEach(el => {
                                    const t = (el.innerText || el.value || el.getAttribute('aria-label') || '').trim();
                                    if (t && (
                                        t.toLowerCase().includes('wireguard') || 
                                        t.toLowerCase().includes('secure core') || 
                                        t.toLowerCase().includes('standard') || 
                                        t.toLowerCase().includes('netshield') || 
                                        t.toLowerCase().includes('moderate nat') || 
                                        t.toLowerCase().includes('nat-pmp') || 
                                        t.toLowerCase().includes('accelerator') ||
                                        t.toLowerCase().includes('router') ||
                                        t.toLowerCase().includes('platform')
                                    )) {
                                        texts.push({tag: el.tagName, role: el.getAttribute('role'), text: t.slice(0, 150)});
                                    }
                                });
                                return texts;
                            }''')
                            if wg_info:
                                captured_data["wireguard_options"]["dom_elements"] = wg_info
                                save_data()
                    except Exception:
                        pass
        except KeyboardInterrupt:
            print("\nInspection stopped by user.")
        finally:
            save_data()
            print(f"💾 Intercepted data saved to {OUT_FILE}")

if __name__ == "__main__":
    main()
