"""
Terminal WebSocket Service for NO ENTRY.
Streams simulated shell commands, executes Red scenario scripts with typing cadence,
and synchronizes kill-chain stage updates and sim_engine events.
"""

import asyncio
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
import yaml
from fastapi import WebSocket, WebSocketDisconnect

from backend.app.config import settings
from backend.app.shell.parser import shell_parser
from backend.app.sim.engine import sim_engine

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"

class TerminalSession:
    """Manages an active WebSocket terminal connection."""

    def __init__(self, websocket: WebSocket):
        self.ws = websocket
        self.active_scenario_task: Optional[asyncio.Task] = None

    async def send_line(self, line: str, delay: float = 0.04):
        """Send a single line to the terminal with carriage return / newline."""
        await self.ws.send_json({
            "type": "output",
            "data": line + "\r\n"
        })
        if delay > 0:
            await asyncio.sleep(delay)

    async def execute_command(self, cmd_str: str):
        """Parse command and stream output lines with realistic terminal pacing."""
        lines = shell_parser.parse_command(cmd_str)
        for line in lines:
            if line == "\033[2J\033[H":
                # Clear screen command
                await self.ws.send_json({"type": "clear"})
            else:
                await self.send_line(line, delay=0.03)

    async def run_scenario_script(self, scenario_id: str):
        """Run one of the 5 red scenario scripts line-by-line."""
        script_file = SCRIPTS_DIR / f"{scenario_id}.yaml"
        if not script_file.exists():
            await self.send_line(f"\033[38;2;255;31;61m[!] Scenario script '{scenario_id}' not found.\033[0m")
            return

        try:
            with open(script_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            await self.send_line(f"\033[38;2;255;31;61m[!] Failed to load script: {e}\033[0m")
            return

        lines: List[Dict[str, Any]] = data.get("lines", [])
        total = len(lines)

        await self.ws.send_json({
            "type": "scenario_start",
            "scenario_id": scenario_id,
            "name": data.get("name", scenario_id),
            "target": data.get("target_host", "unknown"),
            "total_steps": total
        })

        try:
            for idx, item in enumerate(lines):
                text = item.get("text", "")
                stage = item.get("kill_chain_stage", "Execution")
                delay = item.get("delay", 0.8)

                # Send stage progress update to UI
                await self.ws.send_json({
                    "type": "stage",
                    "stage": stage,
                    "step": idx + 1,
                    "total": total,
                    "target": data.get("target_host", "web01")
                })

                # Stream line to terminal
                await self.send_line(text, delay=0.0)

                # Emit matching event into simulation engine
                if item.get("event"):
                    await sim_engine.emit_event(item["event"])

                # Update host state in simulation engine if present
                if item.get("host_update"):
                    hu = item["host_update"]
                    sim_engine.update_host_status(
                        hu.get("host"),
                        hu.get("status"),
                        hu.get("last_alert")
                    )

                # Realistic typing delay before next action
                await asyncio.sleep(delay)

            await self.ws.send_json({
                "type": "scenario_done",
                "scenario_id": scenario_id,
                "message": f"Scenario {scenario_id} execution completed."
            })
        except asyncio.CancelledError:
            try:
                await self.ws.send_json({
                    "type": "scenario_stopped",
                    "scenario_id": scenario_id
                })
                await self.send_line("\033[38;2;255;184;0m[*] Scenario execution stopped by operator.\033[0m")
            except Exception:
                pass

    def stop_scenario(self):
        """Cancel running scenario task."""
        if self.active_scenario_task and not self.active_scenario_task.done():
            self.active_scenario_task.cancel()
            self.active_scenario_task = None

    async def stop_scenario_and_wait(self):
        """Cancel running scenario task and await cleanup before starting another."""
        task = self.active_scenario_task
        self.active_scenario_task = None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

async def handle_terminal_ws(websocket: WebSocket):
    """WebSocket handler for /ws/terminal."""
    await websocket.accept()
    session = TerminalSession(websocket)

    # Initial welcome banner
    await session.send_line("\033[38;2;0;229;255m\033[1mNO ENTRY // OFFENSIVE CONSOLE v2.4\033[0m")
    await session.send_line("\033[38;2;138;147;163mScope: 10.0.0.0/16 Virtual Target Environment (Isolated)\033[0m")
    await session.send_line("Type '\033[38;2;0;229;255mhelp\033[0m' for commands or click a scenario on the left.")
    await session.send_line("")

    try:
        while True:
            raw_msg = await websocket.receive_text()
            if not raw_msg:
                continue

            # Parse message (JSON or plain command)
            try:
                payload = json.loads(raw_msg)
            except Exception:
                payload = {"type": "command", "command": raw_msg}

            msg_type = payload.get("type", "command")

            if msg_type == "command":
                cmd = payload.get("command", "").strip()
                if cmd:
                    await session.execute_command(cmd)

            elif msg_type == "run_scenario":
                sc_id = payload.get("scenario_id", "web-breach")
                await session.stop_scenario_and_wait()
                session.active_scenario_task = asyncio.create_task(session.run_scenario_script(sc_id))

            elif msg_type == "stop_scenario":
                await session.stop_scenario_and_wait()

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        session.stop_scenario()
    except Exception as e:
        session.stop_scenario()
        print(f"Terminal WebSocket error: {e}")
