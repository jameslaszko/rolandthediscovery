from __future__ import annotations
import os
import re
import subprocess
import time
from typing import Iterable, Tuple, Optional
from roland_discovery.util.logging import log_raw_response


_LINE_RE = re.compile(r"^\s*\.?((?P<oid>[0-9]+(?:\.[0-9]+)*))\s*=\s*(?P<rest>.*)$")


class SnmpV2cClient:
    """SNMPv2c wrapper using Net-SNMP CLI with fast health check + retries."""

    def __init__(self, host: str, community: str, timeout: int = 30, retries: int = 2) -> None:
        self.host = host
        self.community = community
        self.timeout = timeout
        self.retries = retries  # Net-SNMP internal retries per command
        self.max_outer_retries = 3
        self.backoff_base = 1.5  # 1.5s → 2.25s → 3.375s
        self._is_healthy = None  # None = not checked, True/False = result

    def _run_subprocess_with_retry(self, cmd: list[str], description: str, health_check: bool = False) -> str:
        attempt = 0
        start_time = time.time()
        while attempt < self.max_outer_retries:
            process = None
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                timeout_val = 5 if health_check else self.timeout * (attempt + 1)
                output, _ = process.communicate(timeout=timeout_val)
                if process.returncode != 0:
                    raise subprocess.CalledProcessError(process.returncode, cmd, output=output)
                print(f"[SNMP] {description} completed in {time.time() - start_time:.1f}s")
                return output.strip()
            except subprocess.TimeoutExpired:
                attempt += 1
                if process:
                    process.kill()
                    try:
                        process.communicate(timeout=5)
                    except:
                        pass
                if attempt == self.max_outer_retries:
                    raise RuntimeError(f"{description} timed out after {self.max_outer_retries} attempts")
                delay = self.backoff_base ** attempt
                print(f"[WARN SNMP] {description} timeout (attempt {attempt}/{self.max_outer_retries}). Killed process. Retrying in {delay:.1f}s...")
                time.sleep(delay)
            except subprocess.CalledProcessError as e:
                attempt += 1
                msg = e.output.strip()
                if attempt == self.max_outer_retries:
                    raise RuntimeError(f"{description} failed after {self.max_outer_retries} attempts: {msg}")
                delay = self.backoff_base ** attempt
                print(f"[WARN SNMP] {description} error (attempt {attempt}/{self.max_outer_retries}): {msg}. Retrying in {delay:.1f}s...")
                time.sleep(delay)
            except Exception as e:
                raise RuntimeError(f"Unexpected error in {description}: {e}")
        raise RuntimeError(f"Max retries exceeded for {description}")

    def _check_snmp_health(self) -> bool:
        """Fast test: try to get sysName with very short timeout + quick retries."""
        if self._is_healthy is not None:
            return self._is_healthy

        cmd = [
            'snmpget',
            '-v2c',
            '-c', self.community,
            '-t', '5',           # 5-second timeout per packet
            '-r', '3',           # 3 fast retries
            self.host,
            '1.3.6.1.2.1.1.5.0'  # sysName - smallest possible query
        ]

        try:
            output = self._run_subprocess_with_retry(cmd, "SNMP health check (sysName)", health_check=True)
            log_raw_response(
                protocol="snmp",
                host=self.host,
                command="snmpget 1.3.6.1.2.1.1.5.0 (health check)",
                raw_output=output,
                success=True
            )
            self._is_healthy = bool(output and '=' in output)
        except Exception as e:
            log_raw_response(
                protocol="snmp",
                host=self.host,
                command="snmpget 1.3.6.1.2.1.1.5.0 (health check)",
                raw_output="",
                success=False,
                error=str(e)
            )
            print(f"[DEBUG SNMP] Health check failed for {self.host}: {str(e)}")
            self._is_healthy = False

        return self._is_healthy

    def get(self, oid: str) -> Optional[str]:
        if not self._check_snmp_health():
            print(f"[SKIP SNMP] Health check failed — skipping get {oid} on {self.host}")
            return None

        cmd = [
            'snmpget',
            '-v2c',
            '-c', self.community,
            '-t', str(self.timeout),
            '-r', str(self.retries),
            self.host,
            oid
        ]
        try:
            output = self._run_subprocess_with_retry(cmd, f"snmpget {oid}")
            log_raw_response(
                protocol="snmp",
                host=self.host,
                command=f"snmpget {oid}",
                raw_output=output,
                success=True
            )
            if '=' not in output:
                return None
            value_part = output.split(' = ', 1)[1].strip()
            if ': ' in value_part:
                value_part = value_part.split(': ', 1)[1].strip()
            return value_part
        except Exception as e:
            print(f"[WARN SNMP] get failed for {oid} after retries: {str(e)}")
            return None

    def walk(self, oid: str, community: str | None = None) -> Iterable[Tuple[str, str]]:
        if not self._check_snmp_health():
            print(f"[SKIP SNMP] Health check failed — skipping walk {oid} on {self.host}")
            return

        comm = community or self.community
        cmd = [
            "snmpwalk",          # Changed to snmpwalk (more reliable on Nexus 9k)
            "-v2c",
            "-c", comm,
            "-t", str(self.timeout),
            "-r", str(self.retries),
            "-On",               # Numeric output
            self.host,
            oid,
        ]
        try:
            output = self._run_subprocess_with_retry(cmd, f"snmpwalk {oid}")
            log_raw_response(
                protocol="snmp",
                host=self.host,
                command=f"snmpwalk {oid}",
                raw_output=output,
                success=True
            )
        except Exception as e:
            log_raw_response(
                protocol="snmp",
                host=self.host,
                command=f"snmpwalk {oid}",
                raw_output="",
                success=False,
                error=str(e)
            )
            print(f"[ERROR SNMP] walk failed for {oid} after retries: {str(e)}")
            return

        if os.getenv("ROLAND_SNMP_DEBUG") == "1":
            print("DEBUG snmpwalk cmd:", " ".join(cmd))
            print("DEBUG stdout:\n", output)

        parsed_any = False
        for line in output.splitlines():
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
            print(f"[WARN SNMP] snmpwalk output couldn't be parsed for OID {oid} (enable ROLAND_SNMP_DEBUG=1)")