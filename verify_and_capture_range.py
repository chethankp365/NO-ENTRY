"""
Playwright Automation Script for NO ENTRY Real Cyber Range Verification & Screenshot Capture.
"""

import asyncio
import os
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = os.path.join(os.getcwd(), "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="msedge", headless=True)
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})

        # Add authenticated session cookie
        from backend.app.api.auth import create_access_token
        token = create_access_token({"sub": "op-0x7f3a"})
        await context.add_cookies([{
            "name": "ne_auth_token",
            "value": token,
            "domain": "127.0.0.1",
            "path": "/",
            "httpOnly": True,
            "secure": False,
        }])

        page = await context.new_page()

        # 1. Navigate directly to Room Workspace
        print("[1] Navigating to Room Workspace...")
        await page.goto("http://127.0.0.1:8000/academy/rooms/red-09-sqli-fundamentals", wait_until="networkidle")
        await page.wait_for_timeout(1500)

        # Dismiss briefing modal if visible
        commence_btn = page.locator("#btnCommenceMission")
        if await commence_btn.is_visible():
            await commence_btn.click()
            await page.wait_for_timeout(500)

        # Ensure lab is in STOPPED state initially
        stop_btn = page.locator("#btnStopLab")
        if await stop_btn.is_visible():
            await stop_btn.click()
            await page.wait_for_timeout(1500)

        # Capture 01: Room Workspace in Stopped State
        p1 = os.path.join(SCREENSHOTS_DIR, "range_01_room_workspace_stopped.png")
        await page.screenshot(path=p1, full_page=False)
        print(f"[✓] Saved: {p1}")

        # 3. Click START LAB to provision real Docker environment
        print("[3] Clicking START LAB...")
        start_btn = page.locator("#btnStartLab")
        await start_btn.click()

        # Wait for terminal online status badge and target IP update
        print("[3] Waiting for Docker container startup...")
        await page.wait_for_selector("#termStatusBadge.online", timeout=45000)
        await page.wait_for_timeout(2500)

        # Capture 02: Room Workspace in Running State
        p2 = os.path.join(SCREENSHOTS_DIR, "range_02_room_workspace_running.png")
        await page.screenshot(path=p2, full_page=False)
        print(f"[✓] Saved: {p2}")

        # 4. Interact with GHOST AI Mentor
        print("[4] Interacting with GHOST AI Mentor...")
        # Step 2: Identify Network & Target
        ghost_steps = page.locator("#ghostStepsList button")
        count = await ghost_steps.count()
        if count >= 3:
            await ghost_steps.nth(1).click()  # Step 2
            await page.wait_for_timeout(600)

        # Request progressive hints
        req_hint_btn = page.locator("#btnGhostRequestHint")
        if await req_hint_btn.is_visible():
            await req_hint_btn.click() # Level 2
            await page.wait_for_timeout(600)
            await req_hint_btn.click() # Level 3
            await page.wait_for_timeout(600)

        # Ask GHOST input
        ask_input = page.locator("#inputGhostAsk")
        ask_btn = page.locator("#btnGhostAsk")
        if await ask_input.is_visible() and await ask_btn.is_visible():
            await ask_input.fill("What port is the target on?")
            await ask_btn.click()
            await page.wait_for_timeout(1500)

        # Capture 03: GHOST Guided Workflow & Hints
        p3 = os.path.join(SCREENSHOTS_DIR, "range_03_ghost_ai_mentor.png")
        await page.screenshot(path=p3, full_page=False)
        print(f"[✓] Saved: {p3}")

        # 5. Execute commands in the terminal via Quick Probes and WebSocket
        print("[5] Executing commands into terminal...")
        # Use terminal keyboard simulation or quick probe
        quick_probes = page.locator(".btn-quick-cmd")
        probe_count = await quick_probes.count()
        for i in range(min(probe_count, 3)):
            btn = quick_probes.nth(i)
            await btn.click()
            await page.wait_for_timeout(1200)

        # Type directly into xterm textarea
        xterm_helper = page.locator(".xterm-helper-textarea")
        if await xterm_helper.is_visible():
            await xterm_helper.focus()
            await page.keyboard.type("whoami && id")
            await page.keyboard.press("Enter")
            await page.wait_for_timeout(1500)
            await page.keyboard.type("ip -br addr")
            await page.keyboard.press("Enter")
            await page.wait_for_timeout(1500)

        # Capture 04: Terminal with Real Output
        p4 = os.path.join(SCREENSHOTS_DIR, "range_04_terminal_real_output.png")
        await page.screenshot(path=p4, full_page=False)
        print(f"[✓] Saved: {p4}")

        # 6. Maximize Fullscreen Operator Workstation (Mode B)
        print("[6] Opening Fullscreen Operator Workstation...")
        max_btn = page.locator("#btnMaximizeWorkstation")
        if await max_btn.is_visible():
            await max_btn.click()
            await page.wait_for_timeout(2000)

            # Click a quick command in full screen (whoami, id, or nmap)
            fs_cmd_whoami = page.locator("#fsQuickCmdGrid button[data-cmd='whoami']")
            if await fs_cmd_whoami.is_visible():
                await fs_cmd_whoami.click()
                await page.wait_for_timeout(1500)

            fs_cmd_nmap = page.locator("#fsQuickCmdGrid button:has-text('nmap scan')")
            if await fs_cmd_nmap.is_visible():
                await fs_cmd_nmap.click()
                await page.wait_for_timeout(2500)

            # Capture 05: Fullscreen Operator Workstation
            p5 = os.path.join(SCREENSHOTS_DIR, "range_05_fullscreen_workstation.png")
            await page.screenshot(path=p5, full_page=False)
            print(f"[✓] Saved: {p5}")

        await browser.close()
        print("[✓] All captures completed successfully!")

if __name__ == "__main__":
    asyncio.run(main())
