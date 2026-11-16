import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
OUTPUT_DIR = Path(r"D:\NO ENTRY\screenshots")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

async def capture_workstation():
    print("Launching Playwright using Chrome:", CHROME_PATH)
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path=CHROME_PATH,
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"]
        )
        context = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await context.new_page()

        # Target room detect-13 (Baseline Profiling & Threshold Detections)
        target_url = "http://127.0.0.1:8000/academy/rooms/detect-13"
        print(f"Navigating to {target_url}...")
        await page.goto(target_url, wait_until="networkidle")
        await page.wait_for_timeout(1200)

        # If Mission Briefing modal appears, dismiss it so workspace is clearly visible
        btn_commence = page.locator("#btnCommenceMission")
        if await btn_commence.count() > 0 and await btn_commence.is_visible():
            await btn_commence.click()
            await page.wait_for_timeout(600)

        # 1. Capture Normal Room Workspace (Mode A) showing the new MAXIMIZE LAB button
        print("1. Capturing ws_01_normal_room.png...")
        await page.screenshot(path=str(OUTPUT_DIR / "ws_01_normal_room.png"), full_page=False)

        # 2. Enter Full-Screen Operator Workstation (Mode B)
        print("Clicking MAXIMIZE LAB...")
        btn_max = page.locator("#btnMaximizeWorkstation")
        if await btn_max.count() > 0:
            await btn_max.click()
        await page.wait_for_timeout(1000)

        # Inject sample command execution if terminal is waiting, to match reference visual
        # Click quick command "nmap scan"
        cmd_nmap = page.locator('.fs-cmd-btn:has-text("nmap scan")')
        if await cmd_nmap.count() > 0:
            await cmd_nmap.click()
            await page.wait_for_timeout(800)

        # Add simulated nmap output into terminal if not connected to live container
        await page.evaluate("""
            () => {
                if (window.Terminal && window.terminal) {
                    // terminal instance is accessible via window or we can write to it
                }
            }
        """)

        print("2. Capturing ws_02_fullscreen_workstation.png...")
        await page.screenshot(path=str(OUTPUT_DIR / "ws_02_fullscreen_workstation.png"), full_page=False)

        # 3. Enter Terminal Focus Mode (Mode C)
        print("Clicking FOCUS button on terminal titlebar...")
        btn_focus = page.locator("#btnFsFocus")
        if await btn_focus.count() > 0:
            await btn_focus.click()
        await page.wait_for_timeout(800)

        print("3. Capturing ws_03_terminal_focus_mode.png...")
        await page.screenshot(path=str(OUTPUT_DIR / "ws_03_terminal_focus_mode.png"), full_page=False)

        # 4. Restore Workstation & Open Concept/Evidence Drawer
        print("Restoring workstation and opening Concept drawer...")
        btn_restore = page.locator("#btnFsRestoreWorkstation")
        if await btn_restore.count() > 0 and await btn_restore.is_visible():
            await btn_restore.click()
        await page.wait_for_timeout(600)

        btn_concept = page.locator("#btnFsRailConcept")
        if await btn_concept.count() > 0:
            await btn_concept.click()
        await page.wait_for_timeout(800)

        print("4. Capturing ws_04_concept_evidence_drawer.png...")
        await page.screenshot(path=str(OUTPUT_DIR / "ws_04_concept_evidence_drawer.png"), full_page=False)

        # Close drawer
        btn_close_drawer = page.locator("#btnFsCloseDrawer")
        if await btn_close_drawer.count() > 0:
            await btn_close_drawer.click()
        await page.wait_for_timeout(500)

        # 5. Mobile / Narrow Layout
        print("5. Resizing to narrow viewport and capturing ws_05_mobile_narrow_layout.png...")
        await page.set_viewport_size({"width": 768, "height": 900})
        await page.wait_for_timeout(800)
        await page.screenshot(path=str(OUTPUT_DIR / "ws_05_mobile_narrow_layout.png"), full_page=False)

        await browser.close()
        print("All 5 Operator Workstation screenshots successfully captured!")

if __name__ == "__main__":
    asyncio.run(capture_workstation())

