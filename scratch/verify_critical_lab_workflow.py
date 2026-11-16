import asyncio
import os
import re
from playwright.async_api import async_playwright

ARTIFACT_DIR = r"C:\Users\cheth\.gemini\antigravity\brain\02e89d27-70e0-4eb7-9667-6a1aef4804a2"

async def run_verification():
    os.environ.pop("http_proxy", None)
    os.environ.pop("https_proxy", None)
    os.environ.pop("all_proxy", None)
    os.environ["NO_PROXY"] = "127.0.0.1,localhost"

    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="msedge", headless=True)
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        page = await context.new_page()
        page.on("console", lambda msg: print(f"    [PAGE CONSOLE] {msg.type}: {msg.text}"))
        page.on("pageerror", lambda err: print(f"    [PAGE ERROR] {err}"))

        # Step 1: Open Room 13
        print("[1] Navigating to Room 13...")
        await page.goto("http://127.0.0.1:8000/room/room-13-baseline-profiling", wait_until="networkidle")
        await page.wait_for_timeout(800)

        # Dismiss briefing modal if visible
        try:
            btn_commence = page.locator("#btnCommenceMission")
            if await btn_commence.is_visible():
                await btn_commence.click()
                print("    Dismissed briefing modal.")
                await page.wait_for_timeout(400)
        except Exception:
            pass

        # If lab was already left running from prior test, cleanly stop it first
        if await page.locator("#btnFsStopLab").is_visible():
            print("    Prior lab session detected active. Stopping first for clean test lifecycle...")
            await page.click("#btnFsStopLab")
            await page.wait_for_selector("#fsStatusPill.offline", timeout=30000)
            await page.wait_for_timeout(1000)

        # Step 2: Confirm initial state is STOPPED
        status_text = await page.locator("#fsStatusText").text_content()
        intel_status = await page.locator("#fsIntelStatus").text_content()
        timer_text = await page.locator("#fsTimerVal").text_content()
        session_count = await page.locator("#fsSessionCount").text_content()
        print(f"[2] Initial state: status='{status_text}', intel='{intel_status.strip()}', timer='{timer_text}', sessions='{session_count.strip()}'")

        # Capture Screenshot 1: Stopped State
        shot1 = os.path.join(ARTIFACT_DIR, "critical_01_lab_stopped.png")
        await page.screenshot(path=shot1, full_page=True)
        print(f"    Saved: {shot1}")

        # Step 3: Click START LAB
        print("[3] Clicking START LAB...")
        await page.click("#btnFsStartLab")
        
        # Wait for lab to reach ONLINE state
        print("    Waiting for backend container deployment and network provisioning...")
        await page.wait_for_selector("#fsStatusPill.online", timeout=45000)
        await page.wait_for_timeout(2000)

        online_status = await page.locator("#fsStatusText").text_content()
        target_ip_el = await page.locator("#fsIntelIp").text_content()
        operator_ip_el = await page.locator("#fsIntelOperatorIp").text_content()
        session_ip_el = await page.locator("#fsSessionIp").text_content()
        active_btn_stop = await page.locator("#btnFsStopLab").is_visible()

        target_ip = target_ip_el.replace("📋", "").strip()
        operator_ip = operator_ip_el.strip()
        session_ip = session_ip_el.strip()

        print(f"[4] Lab ONLINE: Status='{online_status}', Target IP='{target_ip}', Operator IP='{operator_ip}', Session IP='{session_ip}', StopBtn Visible={active_btn_stop}")

        # Capture Screenshot 2: Online State with HUD & Intelligence
        shot2 = os.path.join(ARTIFACT_DIR, "critical_02_lab_online.png")
        await page.screenshot(path=shot2, full_page=True)
        print(f"    Saved: {shot2}")

        # Step 4: Execute real commands in persistent shell
        print("[5] Executing sequential commands in persistent terminal...")
        
        # Send commands via page evaluation or quick commands
        async def exec_cmd(cmd: str):
            print(f"    > Executing: {cmd}")
            await page.evaluate(f"executeWorkstationCommand('{cmd}')")
            await page.wait_for_timeout(1800)

        await exec_cmd("whoami")
        await exec_cmd("id")
        await exec_cmd("ip -br addr")
        await exec_cmd("pwd")
        await exec_cmd("cd /tmp")
        await exec_cmd("pwd")
        await exec_cmd("export TEST_VALUE=NOENTRY")
        await exec_cmd("echo $TEST_VALUE")
        await exec_cmd("cd ~")
        await exec_cmd("pwd")
        await exec_cmd(f"nmap -sV -F {target_ip}")
        await page.wait_for_timeout(3500)
        await exec_cmd(f"curl -s -i http://{target_ip}:8089/")
        await page.wait_for_timeout(2000)

        # Capture Screenshot 3: Terminal with Real Persistent Commands
        shot3 = os.path.join(ARTIFACT_DIR, "critical_03_terminal_persistent_exec.png")
        await page.screenshot(path=shot3, full_page=True)
        print(f"    Saved: {shot3}")

        # Step 5: Open Hints Drawer
        print("[6] Opening Tactical Hints Drawer...")
        await page.click("#btnFsRailHints")
        await page.wait_for_selector("#fsDrawerOverlay", state="visible", timeout=5000)
        await page.wait_for_timeout(600)

        shot4 = os.path.join(ARTIFACT_DIR, "critical_04_hints_drawer.png")
        await page.screenshot(path=shot4, full_page=True)
        print(f"    Saved: {shot4}")

        # Close hints drawer before opening GHOST
        await page.click("#btnFsCloseDrawer")
        await page.wait_for_timeout(400)

        # Step 6: Open GHOST AI Mentor Drawer
        print("[7] Opening GHOST AI Mentor Drawer...")
        await page.click("#btnFsRailGhost")
        await page.wait_for_selector("#fsGhostGuideContainer", state="visible", timeout=8000)
        await page.wait_for_timeout(1500)

        shot5 = os.path.join(ARTIFACT_DIR, "critical_05_ghost_mentor.png")
        await page.screenshot(path=shot5, full_page=True)
        print(f"    Saved: {shot5}")

        # Close Drawer and return to terminal
        await page.click("#btnFsCloseDrawer")
        await page.wait_for_timeout(400)

        # Step 7: Click STOP LAB and verify cleanup
        print("[8] Clicking STOP LAB and verifying container cleanup...")
        await page.click("#btnFsStopLab")
        await page.wait_for_selector("#fsStatusPill.offline", timeout=30000)
        await page.wait_for_timeout(1000)

        post_stop_status = await page.locator("#fsStatusText").text_content()
        post_stop_ip = await page.locator("#fsIntelIp").text_content()
        post_stop_sessions = await page.locator("#fsSessionCount").text_content()
        print(f"    Post-stop status: '{post_stop_status}', Intel IP: '{post_stop_ip.strip()}', Sessions: '{post_stop_sessions.strip()}'")

        shot6 = os.path.join(ARTIFACT_DIR, "critical_06_lab_stopped_cleanup.png")
        await page.screenshot(path=shot6, full_page=True)
        print(f"    Saved: {shot6}")

        await context.close()
        await browser.close()
        print("[+] End-to-end browser verification completed successfully!")

if __name__ == "__main__":
    asyncio.run(run_verification())
