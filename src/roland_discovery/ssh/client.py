import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from netmiko import ConnectHandler, NetmikoTimeoutException

@dataclass
class SshProfile:
    username: str
    password: str
    port: int = 22
    timeout: int = 30
    connect_timeout: int = 20
    command_timeout: int = 60          # Netmiko uses this per command
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

    def connect(self):
        device = {
            "device_type": "cisco_ios",
            "host": self.host,
            "username": self.profile.username,
            "password": self.profile.password,
            "port": self.profile.port,
            "fast_cli": False,                  # CRITICAL for old IOS
            "global_delay_factor": 2.0,         # extra patience for old 3850
            "timeout": self.profile.connect_timeout,
            "session_timeout": 120,
        }
        try:
            self.connection = ConnectHandler(**device)
            if self.debug:
                print(f"[SSH] Netmiko connected to {self.host} (cisco_ios driver)")
        except Exception as e:
            if self.debug:
                print(f"[SSH] Connect failed: {e}")
            raise

    def run_commands(self, commands: List[str], disable_paging: bool = True) -> Dict[str, str]:
        if not self.connection:
            self.connect()

        results = {}
        try:
            # Minimal paging disable (Netmiko handles this very safely)
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
                        delay_factor=2,           # extra delay for old IOS
                        max_loops=200,            # allow very long output
                        strip_command=True,
                        strip_prompt=True
                    )
                    results[cmd] = output.strip()
                    if self.debug:
                        print(f"[SSH shell ← {self.host}] Got {len(output)} chars for '{cmd}'")
                except NetmikoTimeoutException:
                    if self.debug:
                        print(f"[SSH] Timeout on command: {cmd}")
                    raise

            return results

        except Exception as e:
            if self.debug:
                print(f"[SSH shell error on {self.host}]: {e}")
            raise
        finally:
            if self.connection:
                try:
                    self.connection.disconnect()
                except:
                    pass

    def close(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except:
                pass