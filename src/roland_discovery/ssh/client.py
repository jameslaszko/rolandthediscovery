import paramiko
import re
import time
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class SshProfile:
    username: str
    password: str
    port: int = 22
    timeout: int = 15               # general / overall timeout
    connect_timeout: int = 10
    command_timeout: int = 30
    log_path: str = field(default_factory=lambda: "out/ssh-paramiko.log")

def load_ssh_profile_from_env() -> Optional[SshProfile]:
    """Load SSH credentials from environment variables (used by build.py)."""
    user = os.getenv("ROLAND_SSH_USER")
    pw = os.getenv("ROLAND_SSH_PASS")
    if not user or not pw:
        return None

    return SshProfile(
        username=user,
        password=pw,
        port=int(os.getenv("ROLAND_SSH_PORT", "22")),
        timeout=int(os.getenv("ROLAND_SSH_TIMEOUT", "15")),
        connect_timeout=int(os.getenv("ROLAND_SSH_CONNECT_TIMEOUT", "10")),
        command_timeout=int(os.getenv("ROLAND_SSH_COMMAND_TIMEOUT", "30")),
        log_path=os.getenv("ROLAND_SSH_LOG", "out/ssh-paramiko.log")
    )


class SshClient:
    def __init__(self, host: str, profile: SshProfile, debug: bool = False):
        self.host = host
        self.profile = profile
        self.debug = debug
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._transport: Optional[paramiko.Transport] = None

        if debug:
            paramiko.common.logging.basicConfig(level=paramiko.common.DEBUG)
            paramiko.util.log_to_file(profile.log_path)

    def _looks_like_alg_mismatch(self, exc: Exception) -> bool:
        msg = str(exc).lower()
        return any(kw in msg for kw in ["algorithm negotiation", "no matching", "key exchange", "host key", "mac", "cipher"])

    def _connect_legacy(self):
        if self.debug:
            print(f"[SSH] Falling back to legacy algorithms for {self.host}")
        transport = paramiko.Transport((self.host, self.profile.port))
        transport.start_client(timeout=self.profile.connect_timeout)

        # Legacy preferences (keep your original list if different)
        transport.get_security_options().kex = [
            'diffie-hellman-group-exchange-sha1',
            'diffie-hellman-group14-sha1',
            'diffie-hellman-group1-sha1',
        ] + list(transport.get_security_options().kex)
        transport.get_security_options().key_types = ['ssh-rsa'] + list(transport.get_security_options().key_types)
        transport.get_security_options().macs = [
            'hmac-sha1', 'hmac-sha1-96'
        ] + list(transport.get_security_options().macs)
        transport.get_security_options().ciphers = [
            'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
            'aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc'
        ] + list(transport.get_security_options().ciphers)

        transport.auth_password(self.profile.username, self.profile.password)
        self._transport = transport

    def connect(self):
        try:
            self.client.connect(
                hostname=self.host,
                port=self.profile.port,
                username=self.profile.username,
                password=self.profile.password,
                allow_agent=False,
                look_for_keys=False,
                timeout=self.profile.connect_timeout
            )
            if self.debug:
                print(f"[SSH] Standard connect succeeded for {self.host}")
        except paramiko.SSHException as e:
            if self._looks_like_alg_mismatch(e):
                self._connect_legacy()
            else:
                raise
        if self.debug:
            print(f"[SSH] Connected to {self.host}")

    def run_commands(self, commands: List[str], disable_paging: bool = True) -> Dict[str, str]:
        channel = None
        try:
            channel = self.client.invoke_shell(term='vt100', width=120, height=500)
            channel.settimeout(self.profile.command_timeout)

            time.sleep(1.2)
            _ = self._read_until_prompt(channel)

            if disable_paging:
                channel.send("terminal length 0\n")
                time.sleep(0.4)
                _ = self._read_until_prompt(channel)

            results = {}
            for cmd in commands:
                if self.debug:
                    print(f"[SSH shell → {self.host}] Sending: {cmd}")
                channel.send(cmd + "\n")
                time.sleep(0.7)
                output = self._read_until_prompt(channel)
                if output.startswith(cmd):
                    output = output[len(cmd):].lstrip()
                output = re.sub(r'\r\n?|\n$', '', output).strip()
                results[cmd] = output
                if self.debug:
                    print(f"[SSH shell ← {self.host}] Got {len(output)} chars for '{cmd}'")

            return results

        except Exception as e:
            if self.debug:
                print(f"[SSH shell error on {self.host}]: {e}")
            raise
        finally:
            if channel:
                try:
                    channel.close()
                except:
                    pass

    def _read_until_prompt(self, channel: paramiko.Channel, max_wait: float = 30.0) -> str:
        output = ""
        start = time.time()
        prompt_re = re.compile(r'[\r\n]([\w\-]+[>#](?:\s*\(config.*?\))?\s*)$', re.M | re.I)

        while time.time() - start < max_wait:
            if channel.recv_ready():
                chunk = channel.recv(8192).decode('utf-8', errors='ignore')
                output += chunk
                if self.debug and len(chunk.strip()) > 0:
                    print(f"[SSH recv chunk] {repr(chunk[:100])}...")

            if prompt_re.search(output):
                match = prompt_re.search(output)
                if match:
                    return output[:match.start()].rstrip()
                return output.rstrip()

            time.sleep(0.08)

        if self.debug:
            print(f"[SSH read timeout on {self.host}] Last output: {output[-300:]}")
        raise TimeoutError(f"Timeout reading from {self.host}")

    def close(self):
        if self.client:
            self.client.close()
        if self._transport:
            self._transport.close()