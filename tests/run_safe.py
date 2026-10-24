#!/usr/bin/env python3
"""Suite locale avec garde réseau/processus et résumé reproductible ; aucune VM."""
import contextlib
from datetime import datetime, timezone
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

LAB = Path(__file__).resolve().parents[1]
REPORT = LAB / "releves/rapports/tests-defense-20260923.json"
DATABASE = LAB / "invite/charges_test/database.py"
ACTOR = ("import pathlib,sys;sys.path.insert(0,sys.argv[1]);import database;"
         "getattr(database,sys.argv[2])(sys.argv[3],float(sys.argv[4]),"
         "racine=pathlib.Path(sys.argv[5]))")


def sources():
    paths = sorted({p for name in ("controleur", "invite", "connecteur", "tests", "provisionnement")
                    for p in (LAB/name).rglob("*.py")} | set(LAB.glob("controleur/*.html")))
    return {str(p.relative_to(LAB)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths}


def main():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(LAB / "tests"))
    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex
    original_popen = subprocess.Popen
    permitted = {"loopback_connections": 0, "node_ui_processes": 0, "sqlite_fixture_processes": 0}

    def local_address(address):
        if isinstance(address, tuple):
            try:
                if ipaddress.ip_address(address[0]).is_loopback:
                    permitted["loopback_connections"] += 1
                    return
            except ValueError:
                pass
        raise AssertionError("réseau hors loopback interdit par le runner")

    def connect(sock, address):
        local_address(address)
        return original_connect(sock, address)

    def connect_ex(sock, address):
        local_address(address)
        return original_connect_ex(sock, address)

    def popen(args, *positional, **kwargs):
        if isinstance(args, list) and not kwargs.get("shell"):
            if args == [shutil.which("node"), "-"]:
                permitted["node_ui_processes"] += 1
                return original_popen(args, *positional, **kwargs)
            python = args and args[0] == sys.executable
            cli = (len(args) == 7 and args[1:3] == [str(DATABASE), "status"]
                   and args[3] == "--run-id" and args[5] == "--path")
            actor = (len(args) == 9 and args[1:4] == ["-u", "-c", ACTOR]
                     and args[4] == str(DATABASE.parent) and args[5] in ("lock", "tamper")
                     and Path(args[8]).resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()))
            if python and (cli or actor):
                permitted["sqlite_fixture_processes"] += 1
                return original_popen(args, *positional, **kwargs)
        raise AssertionError("processus externe interdit par le runner")

    before = sources()
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.monotonic()
    with patch.object(subprocess, "Popen", new=popen), \
            patch.object(socket.socket, "connect", new=connect), \
            patch.object(socket.socket, "connect_ex", new=connect_ex), \
            contextlib.redirect_stdout(io.StringIO()):
        suite = unittest.TestLoader().discover(str(LAB / "tests"), pattern="test_*.py")
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    after = sources()
    report = {
        "schema": "sawm-local-tests/v1", "started_at": started,
        "duration_s": round(time.monotonic() - t0, 3),
        "status": "passed" if result.wasSuccessful() else "failed",
        "tests_run": result.testsRun, "failures_count": len(result.failures),
        "errors_count": len(result.errors), "skipped_count": len(result.skipped),
        "failures": [{"test": test.id(), "detail_tail": trace[-1000:]}
                     for test, trace in result.failures + result.errors],
        "command": "PYTHONDONTWRITEBYTECODE=1 " + shlex.join([sys.executable, str(Path(__file__).resolve())]),
        "working_directory": str(LAB), "python_version": sys.version,
        "method": {
            "discovery": "tests/test_*.py", "vm_commands": "blocked",
            "network": "Python connect/connect_ex: numeric loopback addresses only",
            "subprocess": "Only Node stdin UI test and SQLite test actors in temporary directories",
            "limits": "These are guards around trusted local tests, not an operating-system sandbox.",
        },
        "permitted_local_operations": permitted,
        "sources_unchanged_during_run": before == after,
        "source_sha256": before,
        "sources_changed_during_run": sorted(k for k in before.keys() | after.keys()
                                              if before.get(k) != after.get(k)),
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "tests_run", "failures_count", "errors_count",
                                           "sources_unchanged_during_run")}, ensure_ascii=False))
    for failure in report["failures"]:
        print(json.dumps(failure, ensure_ascii=False))
    print(REPORT)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
