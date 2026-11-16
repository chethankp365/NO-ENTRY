import asyncio
import os
from pathlib import Path
from playwright.async_api import async_playwright

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
OUTPUT_DIR = Path(r"D:\NO ENTRY\screenshots")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

async def capture_all():
    print("Launching Chromium using local Chrome:", CHROME_PATH)
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path=CHROME_PATH,
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"]
        )
        context = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await context.new_page()

        # 1. Landing Page Header (Showing removed Docs link)
        print("1. Capturing Landing Header...")
        await page.goto("http://127.0.0.1:8000/", wait_until="networkidle")
        await page.wait_for_timeout(1000)
        await page.screenshot(path=str(OUTPUT_DIR / "01_landing_header_no_docs.png"), full_page=False)

        # 2. Access Page - Register Tab
        print("2. Capturing Access Register Tab...")
        await page.goto("http://127.0.0.1:8000/access", wait_until="networkidle")
        await page.wait_for_timeout(800)
        tab_reg = page.locator("#tabRegister")
        if await tab_reg.count() > 0:
            await tab_reg.click()
            await page.wait_for_timeout(500)
        await page.screenshot(path=str(OUTPUT_DIR / "02_access_register_tab.png"))

        # 3. Access Page - Sign In Tab
        print("3. Capturing Access Sign In Tab...")
        tab_sign = page.locator("#tabSignIn")
        if await tab_sign.count() > 0:
            await tab_sign.click()
            await page.wait_for_timeout(500)
        await page.screenshot(path=str(OUTPUT_DIR / "03_access_login_tab.png"))

        # 4. Watch / SIEM Initial Stream & Techniques
        print("4. Capturing Watch Initial Screen...")
        await page.goto("http://127.0.0.1:8000/watch", wait_until="networkidle")
        await page.wait_for_timeout(2500)
        await page.screenshot(path=str(OUTPUT_DIR / "04_watch_initial_stream_and_techniques.png"))

        # 5. Watch - Active Hunt Results
        print("5. Capturing Watch Active Hunt Results...")
        preset_btn = page.locator(".preset-btn").first
        if await preset_btn.count() > 0:
            await preset_btn.click()
            await page.wait_for_timeout(1500)
        await page.screenshot(path=str(OUTPUT_DIR / "05_watch_active_hunt_results.png"))

        # 6. Watch - 60s Live Attack Demo
        print("6. Capturing Watch 60s Live Attack Demo...")
        btn_live = page.locator("#btnLaunchLiveAttack")
        if await btn_live.count() > 0:
            await btn_live.click()
            await page.wait_for_timeout(2000)
        await page.screenshot(path=str(OUTPUT_DIR / "06_watch_live_attack_60s_demo.png"))

        # Close demo modal
        btn_close = page.locator("#btnCloseLiveAttack")
        if await btn_close.count() > 0:
            await btn_close.click()
            await page.wait_for_timeout(500)

        # 7. Room Workspace - Cinematic Terminal
        print("7. Capturing Room Workspace Terminal (red-01)...")
        await page.goto("http://127.0.0.1:8000/academy/rooms/red-01", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        # Close briefing modal if open
        btn_commence = page.locator("#btnCommenceMission")
        if await btn_commence.count() > 0 and await btn_commence.is_visible():
            await btn_commence.click()
            await page.wait_for_timeout(500)
        await page.screenshot(path=str(OUTPUT_DIR / "07_room_workspace_cinematic_terminal.png"))

        # 8. Room Concept - Red Team (8 parts + SVG diagram)
        print("8. Capturing Red Team 8-Part Concept...")
        concept_el = page.locator("#conceptContent")
        if await concept_el.count() > 0:
            await concept_el.scroll_into_view_if_needed()
            await page.wait_for_timeout(500)
        await page.screenshot(path=str(OUTPUT_DIR / "08_room_concept_red_team_8_parts.png"))

        # 9. Room Concept - Blue Team (blue-01)
        print("9. Capturing Blue Team Concept (blue-01)...")
        await page.goto("http://127.0.0.1:8000/academy/rooms/blue-01", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        btn_commence = page.locator("#btnCommenceMission")
        if await btn_commence.count() > 0 and await btn_commence.is_visible():
            await btn_commence.click()
            await page.wait_for_timeout(500)
        await page.screenshot(path=str(OUTPUT_DIR / "09_room_concept_blue_team.png"))

        # 10. Room Concept - Purple Team (purple-01)
        print("10. Capturing Purple Team Concept (purple-01)...")
        await page.goto("http://127.0.0.1:8000/academy/rooms/purple-01", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        btn_commence = page.locator("#btnCommenceMission")
        if await btn_commence.count() > 0 and await btn_commence.is_visible():
            await btn_commence.click()
            await page.wait_for_timeout(500)
        await page.screenshot(path=str(OUTPUT_DIR / "10_room_concept_purple_team.png"))

        # 11. Room Concept - Detection Engineering (detection-01)
        print("11. Capturing Detection Engineering Concept (detection-01)...")
        await page.goto("http://127.0.0.1:8000/academy/rooms/detection-01", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        btn_commence = page.locator("#btnCommenceMission")
        if await btn_commence.count() > 0 and await btn_commence.is_visible():
            await btn_commence.click()
            await page.wait_for_timeout(500)
        await page.screenshot(path=str(OUTPUT_DIR / "11_room_concept_detection_engineering.png"))

        # 12. User Profile Page
        print("12. Capturing User Profile Page...")
        await page.goto("http://127.0.0.1:8000/profile", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=str(OUTPUT_DIR / "12_user_profile_page.png"))

        await browser.close()
        print("All 12 screenshots captured successfully!")

if __name__ == "__main__":
    asyncio.run(capture_all())

