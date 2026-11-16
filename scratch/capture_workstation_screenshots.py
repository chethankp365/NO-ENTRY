import asyncio
import os
from playwright.async_api import async_playwright

ARTIFACT_DIR = r"C:\Users\cheth\.gemini\antigravity\brain\02e89d27-70e0-4eb7-9667-6a1aef4804a2"

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="msedge", headless=True)
        context = await browser.new_context(viewport={"width": 1600, "height": 900})
        page = await context.new_page()

        # Step 1: Open Room 13 in Stopped State
        print("[1] Navigating to Room 13...")
        await page.goto("http://127.0.0.1:8000/academy/detect-13")
        await page.wait_for_timeout(1000)

        # Dismiss briefing modal if visible
        try:
            commence_btn = page.locator("#btnCommenceMission")
            if await commence_btn.is_visible():
                await commence_btn.click()
                await page.wait_for_timeout(500)
        except Exception as e:
            print("Modal dismiss:", e)

        # Capture 1: Room Workspace in initial state
        img1 = os.path.join(ARTIFACT_DIR, "workstation_01_stopped.png")
        await page.screenshot(path=img1)
        print(f"Captured: {img1}")

        # Step 2: Start Lab session
        print("[2] Starting Lab...")
        btn_start = page.locator("#btnStartLab")
        if await btn_start.is_visible():
            await btn_start.click()
            try:
                await page.wait_for_selector(".term-status-badge.online, .fs-status-pill.online", timeout=25000)
            except Exception:
                pass
            await page.wait_for_timeout(2500)

        # Step 3: Open Full-Screen Operator Workstation
        print("[3] Maximizing Workstation...")
        btn_max = page.locator("#btnMaximizeWorkstation")
        if await btn_max.is_visible():
            await btn_max.click()
            await page.wait_for_timeout(2000)

        # Capture 2: Fullscreen Workstation Online
        img2 = os.path.join(ARTIFACT_DIR, "workstation_02_fullscreen_online.png")
        await page.screenshot(path=img2)
        print(f"Captured: {img2}")

        # Step 4: Execute Quick Command (nmap scan)
        print("[4] Executing nmap scan...")
        nmap_btn = page.locator("#fsQuickCmdGrid .fs-cmd-btn >> text='nmap scan'")
        if await nmap_btn.is_visible():
            await nmap_btn.click()
            await page.wait_for_timeout(8000)

        # Capture 3: Terminal with Nmap Output
        img3 = os.path.join(ARTIFACT_DIR, "workstation_03_terminal_real_nmap.png")
        await page.screenshot(path=img3)
        print(f"Captured: {img3}")

        # Step 5: Test persistence commands directly via terminal input
        print("[5] Executing persistence commands in terminal...")
        await page.keyboard.type("cd /tmp")
        await page.keyboard.press("Enter")
        await page.wait_for_timeout(1200)

        await page.keyboard.type("pwd")
        await page.keyboard.press("Enter")
        await page.wait_for_timeout(1200)

        await page.keyboard.type("export PERSIST_DEMO=range_verified_success")
        await page.keyboard.press("Enter")
        await page.wait_for_timeout(1200)

        await page.keyboard.type("echo $PERSIST_DEMO")
        await page.keyboard.press("Enter")
        await page.wait_for_timeout(1200)

        # Capture 4: Terminal with verified persistence
        img4 = os.path.join(ARTIFACT_DIR, "workstation_04_terminal_persistence.png")
        await page.screenshot(path=img4)
        print(f"Captured: {img4}")

        # Step 6: Test HINTS Drawer in Workstation
        print("[6] Opening Hints drawer in workstation...")
        hints_btn = page.locator("#btnFsRailHints")
        if await hints_btn.is_visible():
            await hints_btn.click()
            await page.wait_for_timeout(1000)

        # Capture 5: Hints Drawer in Workstation
        img5 = os.path.join(ARTIFACT_DIR, "workstation_05_hints_drawer.png")
        await page.screenshot(path=img5)
        print(f"Captured: {img5}")

        # Close browser
        await browser.close()
        print("Playwright capture workflow completed successfully.")

if __name__ == "__main__":
    asyncio.run(main())
