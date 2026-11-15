"""
WebSocket Terminal Bridge for NO ENTRY Academy.
Connects xterm.js in the browser to the active attacker container or process runner.
Streams output with VT100 / ANSI escape sequences.
"""

import asyncio
import json
from typing import Optional
from fastapi import WebSocket, WebSocketDisconnect

from backend.app.labs.manager import lab_manager
from backend.app.db.models import User


class AcademyTerminalHandler:
    async def handle_connection(
        self,
        websocket: WebSocket,
        room_id: str,
        user: User,
    ):
        await websocket.accept()

        # Check for active lab session or launch if requested
        session_info = lab_manager.get_user_session(user.operator_id, room_id)

        # Welcome banner
        banner_lines = [
            "\r\n\x1b[38;2;0;229;255m╔══════════════════════════════════════════════════════════════╗\x1b[0m\r\n",
            "\x1b[38;2;0;229;255m║  NO ENTRY ACADEMY // OPERATOR ATTACK WORKSTATION             ║\x1b[0m\r\n",
            "\x1b[38;2;0;229;255m╚══════════════════════════════════════════════════════════════╝\x1b[0m\r\n",
            f"\x1b[90mOperator:\x1b[0m \x1b[32m{user.operator_id}\x1b[0m  |  \x1b[90mRoom:\x1b[0m \x1b[36m{room_id}\x1b[0m\r\n",
        ]

        if session_info and session_info.status == "RUNNING":
            if session_info.runner_mode == "docker":
                mode_badge = "\x1b[32mDOCKER (ISOLATED CONTAINER // WSL 2 ENGINE)\x1b[0m"
            else:
                mode_badge = "\x1b[33mEMULATED (PROCESS RUNNER)\x1b[0m"

            banner_lines.append(f"\x1b[90mRunner Engine:\x1b[0m {mode_badge}\r\n")
            banner_lines.append(
                f"\x1b[90mTarget Host:\x1b[0m \x1b[38;2;255;31;61m{session_info.target_ip}:{session_info.target_port}\x1b[0m "
                f"(\x1b[34mInternal Lab Network // Egress Disabled\x1b[0m)\r\n"
            )
            banner_lines.append(
                f"\x1b[90mAvailable CLI tools:\x1b[0m nmap, curl, python3, jq, nc, ip, whoami, id, ls, cat, chmod, ps, grep, clear\r\n"
                f"\x1b[32mTarget is ready! Run: curl -s http://{session_info.target_ip}:{session_info.target_port}/ or inspect files to begin.\x1b[0m\r\n\r\n"
            )
        else:
            d_status, d_msg, d_guidance = lab_manager.get_docker_status()
            if d_status.value != "DOCKER_AVAILABLE":
                banner_lines.append(f"\x1b[31m[!] DOCKER DAEMON STATUS: {d_status.value}\x1b[0m\r\n")
                banner_lines.append(f"\x1b[33m    {d_msg}\x1b[0m\r\n")
                banner_lines.append(f"\x1b[36m    GUIDANCE: {d_guidance}\x1b[0m\r\n\r\n")
            else:
                banner_lines.append("\x1b[32m[✓] DOCKER RUNTIME AVAILABLE\x1b[0m\r\n")
                banner_lines.append("\x1b[33m[!] Lab environment is currently offline.\x1b[0m\r\n")
                banner_lines.append(
                    "\x1b[90mClick \x1b[0m\x1b[32m'START LAB'\x1b[0m \x1b[90mabove to spawn your isolated target and attacker containers.\x1b[0m\r\n\r\n"
                )

        for line in banner_lines:
            await websocket.send_json({"type": "output", "data": line})

        prompt = "\x1b[38;2;0;229;255moperator@noentry\x1b[0m:\x1b[34m~\x1b[0m$ "
        await websocket.send_json({"type": "output", "data": prompt})

        cmd_buffer = ""

        try:
            while True:
                msg = await websocket.receive_text()
                try:
                    payload = json.loads(msg)
                except Exception:
                    payload = {"type": "input", "data": msg}

                msg_type = payload.get("type", "input")

                if msg_type == "command":
                    cmd = (payload.get("command") or "").strip()
                    await self._run_command(websocket, user, room_id, cmd, prompt)
                elif msg_type == "input":
                    char = payload.get("data", "")
                    if char in ("\r", "\n"):
                        await websocket.send_json({"type": "output", "data": "\r\n"})
                        exec_cmd = cmd_buffer.strip()
                        cmd_buffer = ""
                        if exec_cmd:
                            await self._run_command(websocket, user, room_id, exec_cmd, prompt)
                        else:
                            await websocket.send_json({"type": "output", "data": prompt})
                    elif char in ("\x7f", "\x08"):  # Backspace
                        if len(cmd_buffer) > 0:
                            cmd_buffer = cmd_buffer[:-1]
                            await websocket.send_json({"type": "output", "data": "\b \b"})
                    elif char == "\x03":  # Ctrl+C
                        cmd_buffer = ""
                        await websocket.send_json({"type": "output", "data": "^C\r\n" + prompt})
                    else:
                        cmd_buffer += char
                        await websocket.send_json({"type": "output", "data": char})

        except WebSocketDisconnect:
            pass

    async def _run_command(
        self,
        websocket: WebSocket,
        user: User,
        room_id: str,
        cmd: str,
        prompt: str,
    ):
        if not cmd:
            await websocket.send_json({"type": "output", "data": prompt})
            return

        session_info = lab_manager.get_user_session(user.operator_id, room_id)
        if not session_info or session_info.status != "RUNNING":
            err_msg = (
                "\r\n\x1b[31m[-] Lab session is not active. Please click 'START LAB' to launch.\x1b[0m\r\n"
            )
            await websocket.send_json({"type": "output", "data": err_msg + prompt})
            return

        out = await lab_manager.execute_in_session(
            session_info.session_id, user.operator_id, cmd
        )

        formatted_out = out.replace("\n", "\r\n")
        if not formatted_out.endswith("\r\n"):
            formatted_out += "\r\n"

        await websocket.send_json({"type": "output", "data": formatted_out})
        await websocket.send_json({"type": "output", "data": prompt})


academy_terminal_handler = AcademyTerminalHandler()

