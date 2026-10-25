import os
import sys
import time
import json
import base64
import subprocess
import urllib.request
import asyncio
from pathlib import Path
from PIL import Image

try:
    import websockets
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "websockets"])
    import websockets

SCREENSHOTS_DIR = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


async def main():
    print("1. Launching headless Chrome with remote debugging...")
    chrome_proc = subprocess.Popen([
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "--headless=new",
        "--remote-debugging-port=9222",
        "--user-data-dir=/tmp/chrome_cdp_profile_final2",
        "--window-size=1440,1100",
        "--no-first-run",
        "--no-default-browser-check",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    ws_url = None
    for _ in range(30):
        try:
            req = urllib.request.Request("http://127.0.0.1:9222/json/new?http://localhost:8501", method="PUT")
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                ws_url = data.get("webSocketDebuggerUrl")
                if ws_url:
                    break
        except Exception:
            time.sleep(0.3)

    if not ws_url:
        print("Failed to connect to Chrome CDP.")
        chrome_proc.terminate()
        return False

    print(f"Connected to CDP page: {ws_url}")

    async with websockets.connect(ws_url, max_size=50 * 1024 * 1024) as ws:
        msg_id = 1

        async def send_cmd(method, params=None):
            nonlocal msg_id
            curr_id = msg_id
            msg_id += 1
            payload = {"id": curr_id, "method": method, "params": params or {}}
            await ws.send(json.dumps(payload))
            while True:
                raw = await ws.recv()
                res = json.loads(raw)
                if res.get("id") == curr_id:
                    return res.get("result", {})

        await send_cmd("Page.enable")
        await send_cmd("Runtime.enable")
        await send_cmd("DOM.enable")

        print("2. Waiting for Streamlit application to render...")
        for _ in range(40):
            res = await send_cmd("Runtime.evaluate", {
                "expression": "Boolean(document.querySelector('[data-testid=\"stMain\"]')) && document.querySelectorAll('.stat-card').length >= 4",
                "returnByValue": True
            })
            if res.get("result", {}).get("value") is True:
                print("App rendered with 4 stat cards!")
                break
            await asyncio.sleep(0.5)

        # Allow layout & styles to settle
        await asyncio.sleep(2.0)

        # 3. Ensure scrolled to top and capture Studio Overview
        print("3. Resetting scrollTop to 0 and capturing streamlit_studio.png...")
        await send_cmd("Runtime.evaluate", {
            "expression": """
            (() => {
                const el = document.querySelector('[data-testid="stMain"]');
                if (el) el.scrollTop = 0;
                return el ? el.scrollTop : -1;
            })()
            """,
            "returnByValue": True
        })
        await asyncio.sleep(1.0)

        snap1 = await send_cmd("Page.captureScreenshot", {"format": "png"})
        img1_data = base64.b64decode(snap1["data"])
        out1 = SCREENSHOTS_DIR / "streamlit_studio.png"
        out1.write_bytes(img1_data)
        print(f"✓ Saved {out1} ({len(img1_data)} bytes)")

        # 4. Scroll stMain container to 1100 to show the Before/After comparison and audit proofs
        print("4. Scrolling stMain to 1100...")
        scroll_res = await send_cmd("Runtime.evaluate", {
            "expression": """
            (() => {
                const el = document.querySelector('[data-testid="stMain"]');
                if (el) el.scrollTop = 1100;
                return el ? el.scrollTop : -1;
            })()
            """,
            "returnByValue": True
        })
        print(f"stMain scrolled to: {scroll_res.get('result', {}).get('value')}")
        await asyncio.sleep(2.0)

        # 5. Capture Before/After Slider Screenshot
        print("5. Capturing before_after_slider.png...")
        snap2 = await send_cmd("Page.captureScreenshot", {"format": "png"})
        img2_data = base64.b64decode(snap2["data"])
        out2 = SCREENSHOTS_DIR / "before_after_slider.png"
        out2.write_bytes(img2_data)
        print(f"✓ Saved {out2} ({len(img2_data)} bytes)")

    chrome_proc.terminate()

    # Validate with PIL
    im1 = Image.open(out1)
    im2 = Image.open(out2)
    print(f"Verification: {out1.name} size: {im1.size}, bytes: {len(img1_data)}")
    print(f"Verification: {out2.name} size: {im2.size}, bytes: {len(img2_data)}")
    assert len(img1_data) > 80000, "streamlit_studio.png too small"
    assert len(img2_data) > 80000, "before_after_slider.png too small"
    assert img1_data != img2_data, "Screenshots are identical"
    print("SUCCESS: Both screenshots are distinct, non-empty, and verified!")
    return True


if __name__ == "__main__":
    asyncio.run(main())
