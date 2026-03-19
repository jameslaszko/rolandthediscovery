import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import json
from datetime import datetime, timezone
from roland_discovery.util.logging import log_raw_response

def log_raw_response(
    protocol: str,
    host: str,
    command: str,
    raw_output: str,
    success: bool = True,
    error: Optional[str] = None
):
    log_dir = "out/logs/responses"
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    safe_cmd = command.replace(" ", "-").replace("/", "_")[:50]
    filename = f"{protocol}-{host}-{timestamp}-{safe_cmd}.json"

    data = {
        "timestamp": timestamp,
        "host": host,
        "command": command,
        "raw_output": raw_output,
        "success": success,
        "error": error or None
    }

    path = os.path.join(log_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[LOGGED RAW] {protocol.upper()} response saved: {path}")

@dataclass
class SshProfile:
    username: str
    password: str
    port: int = 22
    timeout: int = 30
    connect_timeout: int = 20
    command_timeout: int = 60  # Netmiko uses this per command
    log_path: str = field(default_factory=lambda: "out/ssh-netmiko.log")

def load_ssh_profile_from_env() -> Optional[SshProfile]:
    user = os.getenv("ROLAND_SSH_USER")
    pw = os.getenv("ROLAND_SSH_PASS")
    if not user or not pw:
        return None
    return SshProfile(
        username=user,
        password=pw,
        port=int(os.getenv("ROLAND_SSH_PORT", "22")),
        timeout=int(os.getenv("ROLAND_SSH_TIMEOUT", "30")),
        connect_timeout=int(os.getenv("ROLAND_SSH_CONNECT_TIMEOUT", "20")),
        command_timeout=int(os.getenv("ROLAND_SSH_COMMAND_TIMEOUT", "60")),
        log_path=os.getenv("ROLAND_SSH_LOG", "out/ssh-netmiko.log")
    )

class SshClient:
    def __init__(self, host: str, profile: SshProfile, debug: bool = False):
        self.host = host
        self.profile = profile
        self.debug = debug
        self.connection = None
        # Retry settings (adjustable)
        self.max_retries = 3
        self.backoff_base = 1.5  # 1.5s → 2.25s → 3.375s

    def _retry_connect(self) -> None:
            """Internal: Connect with retries on transient errors, but no retry on auth failure."""
            attempt = 0
            device = {
                "device_type": "cisco_ios",
                "host": self.host,
                "username": self.profile.username,
                "password": self.profile.password,
                "port": self.profile.port,
                "fast_cli": False,
                "global_delay_factor": 2.0,
                "timeout": self.profile.connect_timeout,
                "session_timeout": 120,
            }

            while attempt < self.max_retries:
                try:
                    self.connection = ConnectHandler(**device)
                    if self.debug:
                        print(f"[SSH] Netmiko connected to {self.host} (attempt {attempt+1})")
                    return
                except NetmikoAuthenticationException as e:
                    # Auth failure: no retry, immediate raise
                    if self.debug:
                        print(f"[SSH] Auth failed (permanent): {e}")
                    raise  # Let caller handle
                except (NetmikoTimeoutException, ConnectionRefusedError, OSError) as e:
                    attempt += 1
                    if attempt == self.max_retries:
                        if self.debug:
                            print(f"[SSH] Connect failed after {self.max_retries} attempts: {e}")
                        raise
                    delay = self.backoff_base ** attempt
                    if self.debug:
                        print(f"[SSH] Transient connect error (attempt {attempt}/{self.max_retries}): {e}. Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                except Exception as e:
                    if self.debug:
                        print(f"[SSH] Unexpected connect error: {e}")
                    raise

            raise RuntimeError(f"Max connect retries exceeded for {self.host}")
            
    def connect(self):
        """Public connect method - uses internal retry."""
        self._retry_connect()

    def run_commands(self, commands: List[str], disable_paging: bool = True) -> Dict[str, str]:
            if not self.connection:
                try:
                    self.connect()  # This may raise NetmikoAuthenticationException directly
                except NetmikoAuthenticationException as e:
                    raise  # Propagate auth failure without retry

            results = {}
            attempt = 0

            while attempt < self.max_retries:
                try:
                    if disable_paging:
                        if self.debug:
                            print(f"[SSH] Disabling paging on {self.host}")
                        self.connection.send_command("terminal length 0", delay_factor=2)

                    for cmd in commands:
                        if self.debug:
                            print(f"[SSH shell → {self.host}] Sending: {cmd}")
                        try:
                            output = self.connection.send_command(
                                cmd,
                                delay_factor=2,
                                max_loops=200,
                                strip_command=True,
                                strip_prompt=True
                            )
                            results[cmd] = output.strip()

                            log_raw_response(
                                protocol="ssh",
                                host=self.host,
                                command=cmd,
                                raw_output=output,
                                success=True
                            )

                            if self.debug:
                                print(f"[SSH shell ← {self.host}] Got {len(output)} chars for '{cmd}'")
                        except NetmikoTimeoutException as e:
                            log_raw_response(
                                protocol="ssh",
                                host=self.host,
                                command=cmd,
                                raw_output="",
                                success=False,
                                error=f"Timeout: {str(e)}"
                            )
                            if self.debug:
                                print(f"[SSH] Timeout on command: {cmd}")
                            raise  # will trigger outer retry

                    return results

                except (NetmikoTimeoutException, OSError, ConnectionResetError) as e:
                    attempt += 1
                    if attempt == self.max_retries:
                        log_raw_response(
                            protocol="ssh",
                            host=self.host,
                            command=",".join(commands),
                            raw_output="",
                            success=False,
                            error=f"Connection failed after retries: {str(e)}"
                        )
                        if self.debug:
                            print(f"[SSH] Failed after {self.max_retries} attempts: {e}")
                        raise
                    delay = self.backoff_base ** attempt
                    if self.debug:
                        print(f"[SSH] Transient error on {self.host} (attempt {attempt}/{self.max_retries}): {e}. Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                    self.connection = None
                    try:
                        self.connect()  # Reconnect attempt
                    except NetmikoAuthenticationException as e:
                        raise  # No retry on auth during reconnect

                except NetmikoAuthenticationException as e:
                    log_raw_response(
                        protocol="ssh",
                        host=self.host,
                        command=",".join(commands),
                        raw_output="",
                        success=False,
                        error=f"Authentication failed: {str(e)}"
                    )
                    if self.debug:
                        print(f"[SSH] Auth failed (permanent): {e}")
                    raise  # No retry on auth failure

                except Exception as e:
                    log_raw_response(
                        protocol="ssh",
                        host=self.host,
                        command=",".join(commands),
                        raw_output="",
                        success=False,
                        error=str(e)
                    )
                    if self.debug:
                        print(f"[SSH shell error on {self.host}]: {e}")
                    raise

            raise RuntimeError(f"Max command retries exceeded for {self.host}")

    def close(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except:
                pass