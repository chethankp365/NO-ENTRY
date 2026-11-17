"""
WebSocket Terminal Bridge for NO ENTRY Academy.
Connects xterm.js in the browser to the active attacker container or process runner.
Maintains genuine persistent interactive Linux shell sessions with working directory tracking,
environment variable persistence, sequential command execution, and ANSI escape sequences.
"""

import asyncio
import json
import os
import re
import shlex
import uuid
from typing import Dict, List, Optional, Tuple
from fastapi import WebSocket, WebSocketDisconnect

from backend.app.labs.manager import lab_manager
from backend.app.labs.base import LabSessionInfo
from backend.app.labs.docker_runner import find_docker_binary, get_docker_env
from backend.app.db.models import User


class InteractiveTerminalSession:
    """
    Maintains a live, stateful interactive process (or high-fidelity emulation)
    so working directory changes (cd), environment exports, and sequential commands
    persist reliably across the learner's entire practical lab session.
    """

    def __init__(self, session_id: str, runner_mode: str, container_id: Optional[str] = None):
        self.session_id = session_id
        self.runner_mode = runner_mode
        self.container_id = container_id
        self.cwd = "~"
        self.env_vars: Dict[str, str] = {}
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.lock = asyncio.Lock()
        self.is_alive = False
        self.recent_output: List[str] = []
        self.last_exit_code: Optional[int] = None

    def _remember_output(self, text: str) -> None:
        if text:
            self.recent_output.extend(text.splitlines())
            self.recent_output = self.recent_output[-25:]

    async def ensure_started(self):
        if self.runner_mode != "docker" or not self.container_id:
            self.is_alive = True
            return

        if self.proc is not None and self.proc.returncode is None:
            self.is_alive = True
            return

        docker_bin = find_docker_binary() or "docker"
        exec_args = [
            docker_bin, "exec", "-i",
            "-u", "operator",
            "-w", "/home/operator",
            "-e", "TERM=xterm-256color",
            "-e", "LANG=C.UTF-8",
            self.container_id,
            "/bin/bash", "--norc"
        ]

        try:
            self.proc = await asyncio.create_subprocess_exec(
                *exec_args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=get_docker_env(),
            )
            self.is_alive = True
            # Read any initial motd / banner output
            sentinel = f"__NOENTRY_INIT_{uuid.uuid4().hex[:6]}__"
            self.proc.stdin.write(f"echo {sentinel}:0:$(pwd)\n".encode("utf-8"))
            await self.proc.stdin.drain()
            while True:
                line_bytes = await self.proc.stdout.readline()
                if not line_bytes:
                    break
                line_str = line_bytes.decode("utf-8", errors="replace")
                if sentinel in line_str:
                    parts = line_str.strip().split(":")
                    if len(parts) >= 3 and parts[2] == "/home/operator":
                        self.cwd = "~"
                    break
        except Exception:
            self.proc = None
            self.is_alive = False

    async def execute(
        self,
        cmd: str,
        websocket: Optional[WebSocket] = None,
        session_info: Optional[LabSessionInfo] = None,
    ) -> Tuple[str, str]:
        cmd = cmd.strip()
        if not cmd:
            return "", self.cwd

        async with self.lock:
            if self.runner_mode == "docker" and self.container_id:
                await self.ensure_started()
                if not self.proc or self.proc.returncode is not None:
                    # Fallback execution via runner if interactive process failed to launch
                    out = await lab_manager._docker_runner.execute_command(self.session_id, cmd)
                    self._remember_output(out)
                    if websocket and out:
                        formatted = out.replace("\n", "\r\n")
                        await websocket.send_json({"type": "output", "data": formatted})
                    return out, self.cwd

                sentinel = f"__NOENTRY_SENTINEL_{uuid.uuid4().hex[:8]}__"
                full_exec_str = f"{cmd}\necho {sentinel}:$?:$(pwd)\n"

                # Drain any unread stale output from previous commands
                while True:
                    try:
                        discard = await asyncio.wait_for(self.proc.stdout.read(4096), timeout=0.01)
                        if not discard:
                            break
                    except asyncio.TimeoutError:
                        break

                try:
                    self.proc.stdin.write(full_exec_str.encode("utf-8"))
                    await self.proc.stdin.drain()
                except Exception:
                    self.proc = None
                    out = await lab_manager._docker_runner.execute_command(self.session_id, cmd)
                    self._remember_output(out)
                    if websocket and out:
                        formatted = out.replace("\n", "\r\n")
                        await websocket.send_json({"type": "output", "data": formatted})
                    return out, self.cwd

                out_chunks: List[str] = []
                exit_code = 0
                while True:
                    try:
                        line_bytes = await asyncio.wait_for(self.proc.stdout.readline(), timeout=180.0)
                    except asyncio.TimeoutError:
                        out_chunks.append("\x1b[31m[-] Command execution timed out.\x1b[0m\n")
                        break

                    if not line_bytes:
                        break

                    line_str = line_bytes.decode("utf-8", errors="replace")
                    sentinel_index = line_str.find(sentinel)
                    if sentinel_index >= 0:
                        command_output = line_str[:sentinel_index]
                        if command_output:
                            out_chunks.append(command_output)
                            if websocket:
                                formatted = command_output.replace("\n", "\r\n")
                                await websocket.send_json({"type": "output", "data": formatted})

                        metadata = line_str[sentinel_index + len(sentinel):].strip()
                        if metadata.startswith(":"):
                            metadata = metadata[1:]
                        parts = metadata.split(":", 1)
                        if len(parts) == 2:
                            try:
                                exit_code = int(parts[0])
                            except ValueError:
                                pass
                            raw_cwd = parts[1]
                            self.cwd = "~" if raw_cwd == "/home/operator" else raw_cwd
                        break

                    out_chunks.append(line_str)
                    if websocket:
                        formatted = line_str.replace("\n", "\r\n")
                        await websocket.send_json({"type": "output", "data": formatted})

                out_text = "".join(out_chunks)
                self.last_exit_code = exit_code
                self._remember_output(out_text)
                if websocket:
                    await websocket.send_json({"type": "exit_status", "code": exit_code})
                if session_info and exit_code == 0:
                    lab_manager._docker_runner._record_command_actions(session_info, cmd, out_text)

                return out_text, self.cwd

            else:
                # High-fidelity Emulated Process Runner state machine
                exit_code = 0
                if cmd.startswith("cd"):
                    parts = cmd.split(maxsplit=1)
                    target = parts[1].strip() if len(parts) > 1 else "~"
                    if target in ("~", "", "$HOME", "/home/operator"):
                        self.cwd = "~"
                    elif target.startswith("/"):
                        self.cwd = target
                    elif target == "..":
                        if self.cwd not in ("~", "/"):
                            self.cwd = os.path.dirname(self.cwd.rstrip("/")) or "/"
                    else:
                        base = "/home/operator" if self.cwd == "~" else self.cwd
                        self.cwd = os.path.normpath(f"{base}/{target}").replace("\\", "/")
                    out_text = ""
                elif cmd.startswith("export "):
                    kv = cmd[7:].strip()
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        self.env_vars[k.strip()] = v.strip().strip("'\"")
                    out_text = ""
                elif cmd == "pwd":
                    disp = "/home/operator" if self.cwd == "~" else self.cwd
                    out_text = f"{disp}\n"
                elif cmd.startswith("echo $"):
                    var_name = cmd[6:].strip()
                    val = self.env_vars.get(var_name, "")
                    out_text = f"{val}\n"
                else:
                    out_text = await lab_manager._process_runner.execute_command(self.session_id, cmd)

                self._remember_output(out_text)
                if websocket and out_text:
                    formatted = out_text.replace("\n", "\r\n")
                    await websocket.send_json({"type": "output", "data": formatted})

                return out_text, self.cwd

    def format_prompt(self) -> str:
        return f"\x1b[38;2;0;255;106moperator@noentry\x1b[0m:\x1b[38;2;0;229;255m{self.cwd}\x1b[0m$ "

    def terminate(self):
        if self.proc:
            try:
                self.proc.terminate()
            except Exception:
                pass
            self.proc = None
        self.is_alive = False


class AcademyTerminalHandler:
    def __init__(self):
        self._sessions: Dict[str, InteractiveTerminalSession] = {}

    def get_or_create_session(self, session_info: LabSessionInfo) -> InteractiveTerminalSession:
        sid = session_info.session_id
        if sid in self._sessions and self._sessions[sid].is_alive:
            return self._sessions[sid]

        sess = InteractiveTerminalSession(
            session_id=sid,
            runner_mode=session_info.runner_mode,
            container_id=session_info.attacker_container_id,
        )
        self._sessions[sid] = sess
        return sess

    def cleanup_session(self, session_id: str):
        sess = self._sessions.pop(session_id, None)
        if sess:
            sess.terminate()

    async def handle_connection(
        self,
        websocket: WebSocket,
        room_id: str,
        user: User,
    ):
        await websocket.accept()

        session_info = lab_manager.get_user_session(user.operator_id, room_id)
        shell_session: Optional[InteractiveTerminalSession] = None

        if (
            session_info
            and session_info.status == "RUNNING"
            and session_info.runner_mode == "docker"
        ):
            shell_session = self.get_or_create_session(session_info)

        # Welcome banner matching operator workstation visual reference
        banner_lines = [
            "\r\n\x1b[38;2;255;31;61m _   _  ____    \x1b[38;2;0;229;255m______ _   _ _______ ______   __\x1b[0m\r\n",
            "\x1b[38;2;255;31;61m| \\ | |/ __ \\  \x1b[38;2;0;229;255m|  ____| \\ | |__   __|  __ \\ \\ / /\x1b[0m\r\n",
            "\x1b[38;2;255;31;61m|  \\| | |  | | \x1b[38;2;0;229;255m| |__  |  \\| |  | |  | |__) \\ V / \x1b[0m\r\n",
            "\x1b[38;2;255;31;61m| . ` | |  | | \x1b[38;2;0;229;255m|  __| | . ` |  | |  |  _  / > <  \x1b[0m\r\n",
            "\x1b[38;2;255;31;61m| |\\  | |__| | \x1b[38;2;0;229;255m| |____| |\\  |  | |  | | \\ \\ / . \\\x1b[0m\r\n",
            "\x1b[38;2;255;31;61m|_| \\_|\\____/  \x1b[38;2;0;229;255m|______|_| \\_|  |_|  |_|  \\_/_/ \\_\\\x1b[0m\r\n",
            "        \x1b[90m- NO ENTRY ACADEMY -\x1b[0m\r\n",
            "        \x1b[38;2;0;229;255m> Learn • Practice • Defend <\x1b[0m\r\n\r\n",
        ]

        if (
            session_info
            and session_info.status == "RUNNING"
            and session_info.runner_mode == "docker"
        ):
            if session_info.runner_mode == "docker":
                mode_badge = "\x1b[38;2;0;255;106mDOCKER (ISOLATED BRIDGE // ROOTLESS)\x1b[0m"
            else:
                mode_badge = "\x1b[38;2;255;184;0mEMULATED PROCESS RUNNER\x1b[0m"

            banner_lines.append(
                f"\x1b[90mOperator Host:\x1b[0m \x1b[38;2;0;229;255moperator@attacker\x1b[0m (\x1b[36m{session_info.attacker_ip}\x1b[0m)  |  "
                f"\x1b[90mTarget:\x1b[0m \x1b[38;2;255;31;61m{session_info.target_hostname}\x1b[0m (\x1b[38;2;255;31;61m{session_info.target_ip}:{session_info.target_port}\x1b[0m)\r\n"
            )
            banner_lines.append(f"\x1b[90mLab Engine:\x1b[0m {mode_badge}  |  \x1b[90mRoom:\x1b[0m \x1b[36m{room_id}\x1b[0m\r\n")
            banner_lines.append(
                f"\x1b[38;2;0;255;106m[✓] LAB ENVIRONMENT ONLINE // ATTACHED TO ISOLATED CONTAINER\x1b[0m\r\n"
                f"\x1b[90mTools:\x1b[0m nmap, curl, python3, jq, nc, tcpdump, whoami, id, ip, ping, grep, cat\r\n\r\n"
            )
        else:
            banner_lines.append(
                "\x1b[90mLab environment in standby. Click \x1b[0m\x1b[38;2;0;255;106m'START LAB'\x1b[0m \x1b[90mabove to spawn the isolated range.\x1b[0m\r\n\r\n"
            )

        for line in banner_lines:
            await websocket.send_json({"type": "output", "data": line})

        current_prompt = shell_session.format_prompt() if shell_session else "\x1b[38;2;0;255;106moperator@noentry\x1b[0m:\x1b[38;2;0;229;255m~\x1b[0m$ "
        await websocket.send_json({"type": "output", "data": current_prompt})

        cmd_buffer = ""
        command_history: List[str] = []
        history_index = 0

        try:
            while True:
                msg = await websocket.receive_text()
                try:
                    payload = json.loads(msg)
                except Exception:
                    payload = {"type": "input", "data": msg}

                msg_type = payload.get("type", "input")

                # Refresh session state if started recently
                if not shell_session:
                    session_info = lab_manager.get_user_session(user.operator_id, room_id)
                    if (
                        session_info
                        and session_info.status == "RUNNING"
                        and session_info.runner_mode == "docker"
                    ):
                        shell_session = self.get_or_create_session(session_info)

                current_prompt = shell_session.format_prompt() if shell_session else "\x1b[38;2;0;255;106moperator@noentry\x1b[0m:\x1b[38;2;0;229;255m~\x1b[0m$ "

                if msg_type == "command":
                    cmd = (payload.get("command") or "").strip()
                    if cmd:
                        command_history.append(cmd)
                        command_history = command_history[-100:]
                        history_index = len(command_history)
                    await self._handle_exec(websocket, shell_session, session_info, user, room_id, cmd)
                elif msg_type == "input":
                    char = payload.get("data", "")
                    if char in ("\r", "\n"):
                        await websocket.send_json({"type": "output", "data": "\r\n"})
                        exec_cmd = cmd_buffer.strip()
                        cmd_buffer = ""
                        if exec_cmd:
                            command_history.append(exec_cmd)
                            command_history = command_history[-100:]
                            history_index = len(command_history)
                            await self._handle_exec(websocket, shell_session, session_info, user, room_id, exec_cmd)
                        else:
                            await websocket.send_json({"type": "output", "data": current_prompt})
                    elif char in ("\x1b[A", "\x1b[B"):
                        if char == "\x1b[A":
                            history_index = max(0, history_index - 1)
                        else:
                            history_index = min(len(command_history), history_index + 1)
                        replacement = (
                            command_history[history_index]
                            if history_index < len(command_history)
                            else ""
                        )
                        erase = "\b \b" * len(cmd_buffer)
                        cmd_buffer = replacement
                        await websocket.send_json(
                            {"type": "output", "data": erase + replacement}
                        )
                    elif char in ("\x7f", "\x08"):  # Backspace
                        if len(cmd_buffer) > 0:
                            cmd_buffer = cmd_buffer[:-1]
                            await websocket.send_json({"type": "output", "data": "\b \b"})
                    elif char == "\x03":  # Ctrl+C
                        cmd_buffer = ""
                        await websocket.send_json({"type": "output", "data": "^C\r\n" + current_prompt})
                    else:
                        cmd_buffer += char
                        await websocket.send_json({"type": "output", "data": char})

        except WebSocketDisconnect:
            pass

    async def _handle_exec(
        self,
        websocket: WebSocket,
        shell_session: Optional[InteractiveTerminalSession],
        session_info: Optional[LabSessionInfo],
        user: User,
        room_id: str,
        cmd: str,
    ):
        if not cmd:
            prompt = shell_session.format_prompt() if shell_session else "\x1b[38;2;0;255;106moperator@noentry\x1b[0m:\x1b[38;2;0;229;255m~\x1b[0m$ "
            await websocket.send_json({"type": "output", "data": prompt})
            return

        if (
            not session_info
            or session_info.status != "RUNNING"
            or session_info.runner_mode != "docker"
        ):
            session_info = lab_manager.get_user_session(user.operator_id, room_id)
            if (
                not session_info
                or session_info.status != "RUNNING"
                or session_info.runner_mode != "docker"
            ):
                err_msg = (
                    "\r\n\x1b[31m[-] No active Docker lab terminal is available. Start the Docker lab before running commands.\x1b[0m\r\n"
                )
                prompt = "\x1b[38;2;0;255;106moperator@noentry\x1b[0m:\x1b[38;2;0;229;255m~\x1b[0m$ "
                await websocket.send_json({"type": "output", "data": err_msg + prompt})
                return

        if not shell_session:
            shell_session = self.get_or_create_session(session_info)

        out, cwd = await shell_session.execute(cmd, websocket=websocket, session_info=session_info)
        prompt = shell_session.format_prompt()
        await websocket.send_json({"type": "output", "data": prompt})


academy_terminal_handler = AcademyTerminalHandler()
