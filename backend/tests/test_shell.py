import pytest
from backend.app.shell.parser import shell_parser

def test_shell_help():
    lines = shell_parser.parse_command("help")
    assert any("SIMULATED OFFENSIVE TERMINAL" in l for l in lines)
    assert any("nmap" in l for l in lines)
    assert any("Lab is isolated" in l for l in lines)

def test_shell_whoami_and_id():
    assert shell_parser.parse_command("whoami") == ["kali"]
    id_out = shell_parser.parse_command("id")
    assert any("uid=1000(kali)" in l for l in id_out)

def test_shell_ls_and_cat():
    ls_out = shell_parser.parse_command("ls")
    assert any("recon_results.txt" in l for l in ls_out)

    cat_out = shell_parser.parse_command("cat recon_results.txt")
    assert any("RANGE RECONNAISSANCE" in l for l in cat_out)

    cat_missing = shell_parser.parse_command("cat non_existent_file.xyz")
    assert any("No such file or directory" in l for l in cat_missing)

def test_shell_nmap_scan():
    # Target web01
    lines = shell_parser.parse_command("nmap -sV web01")
    assert any("Starting Nmap" in l for l in lines)
    assert any("80/tcp" in l for l in lines)
    assert any("nginx 1.18.0" in l for l in lines)

    # Target IP 10.0.0.1 (pfSense)
    lines_pfsense = shell_parser.parse_command("nmap -sV 10.0.0.1")
    assert any("firewall.corp.internal" in l for l in lines_pfsense)
    assert any("lighttpd" in l for l in lines_pfsense)

    # Target outside range
    lines_ext = shell_parser.parse_command("nmap -sV 8.8.8.8")
    assert any("seems down or outside isolated range" in l for l in lines_ext)

def test_shell_sqlmap():
    lines = shell_parser.parse_command("sqlmap -u http://10.0.1.10/api/v1/search?q=test --batch")
    assert any("sqlmap.org" in l for l in lines)
    assert any("corp_crm" in l for l in lines)

def test_shell_hydra():
    lines = shell_parser.parse_command("hydra -l admin -P wordlist.txt 10.0.0.1")
    assert any("Hydra v9.5" in l for l in lines)
    assert any("Suricata" in l or "Connection refused" in l for l in lines)

def test_shell_unknown_command():
    lines = shell_parser.parse_command("totally_fake_cmd_999")
    assert any("command not found" in l for l in lines)
    assert any("Type 'help'" in l for l in lines)
