from __future__ import annotations

import os
import re
import subprocess
from typing import Iterable, Tuple

_LINE_RE = re.compile(r"^\s*\.?((?P<oid>[0-9]+(?:\.[0-9]+)*))\s*=\s*(?P<rest>.*)$")

class SnmpV2cClient:
    """SNMPv2c walker implemented via Net-SNMP 'snmpwalk' CLI."""

    def get(self, oid: str) -> Optional[str]:
        """
        Perform SNMP GET on a single OID.
        Returns the value part (stripped) or None on failure.
        """
        cmd = [
            'snmpget',
            '-v2c',
            '-c', self.community,
            self.host,
            oid
        ]
        try:
            output = subprocess.check_output(
                cmd,
                stderr=subprocess.STDOUT,
                timeout=10  # prevent hangs
            ).decode('utf-8', errors='ignore').strip()

            # Typical output: OID = TYPE: value
            if '=' in output:
                value_part = output.split(' = ', 1)[1].strip()
                # Remove type prefix if present (e.g. "STRING: ", "INTEGER: ", "IpAddress: ")
                if ': ' in value_part:
                    value_part = value_part.split(': ', 1)[1].strip()
                return value_part

            # Fallback: if no '=', return whole output (rare)
            return output

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, UnicodeDecodeError) as e:
            print(f"[WARN SNMP] get failed for {oid}: {str(e)}")
            return None
            
    def __init__(self, host: str, community: str, timeout: int = 2, retries: int = 1) -> None:
        self.host = host
        self.community = community
        self.timeout = timeout
        self.retries = retries

    def walk(self, oid: str, community: str | None = None) -> Iterable[Tuple[str, str]]:
        comm = community or self.community

        cmd = [
            "snmpwalk",
            "-v2c",
            "-c", comm,
            "-t", str(self.timeout),
            "-r", str(self.retries),
            "-On",
            self.host,
            oid,
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)

        if os.getenv("ROLAND_SNMP_DEBUG") == "1":
            print("DEBUG snmpwalk cmd:", " ".join(cmd))
            print("DEBUG returncode:", proc.returncode)
            print("DEBUG stdout:\n", proc.stdout)
            print("DEBUG stderr:\n", proc.stderr)

        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"{self.host}: snmpwalk failed ({proc.returncode}): {msg}")

        parsed_any = False
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            m = _LINE_RE.match(line)
            if not m:
                if os.getenv("ROLAND_SNMP_DEBUG") == "1":
                    print("DEBUG unmatched line:", line)
                continue
            parsed_any = True
            yield m.group("oid"), m.group("rest")

        if not parsed_any:
            raise RuntimeError(f"{self.host}: snmpwalk output couldn't be parsed for OID {oid} (enable ROLAND_SNMP_DEBUG=1)")
