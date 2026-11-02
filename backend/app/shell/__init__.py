"""
Simulated Shell Environment for NO ENTRY.
Provides believable hacker terminal commands and output matching the cyber range.
Completely safe and simulated: executes NO subprocess, os.system, or network calls.
"""

from backend.app.shell.parser import ShellParser, shell_parser

__all__ = ["ShellParser", "shell_parser"]
