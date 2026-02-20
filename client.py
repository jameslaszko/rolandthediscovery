from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import paramiko
from paramiko.ssh_exception import SSHException


@dataclass
class SshProfile:
    username: str
    password: str
    port: int = 22
    connect_timeout: float = 8.0
    banner_timeout: float = 8.0
    auth_timeout: float = 8.0
    command_timeout: float = 10.0


class SshClient:
    """Small helper around Paramiko.

    We prefer an interactive shell so we can disable paging once and run multiple
    commands without fighting per-command session state.
    """

    def __init__(self, host: str, profile: SshProfile):
        self._session = None  # persistent session (optional)
        self.host = host
        self.profile = profile

    @staticmethod
    def _debug_enabled() -> bool:
        # opt-in debug to avoid noisy default output
        v = (os.getenv("ROLAND_SSH_DEBUG") or os.getenv("ROLAND_DEBUG") or "").strip().lower()
        return v in {"1", "true", "yes", "y", "on"}

    def _dbg(self, msg: str) -> None:
        if self._debug_enabled():
            print(f"[roland][ssh-debug] {msg}")

    def _connect(self) -> paramiko.SSHClient:
        """Connect with Paramiko.

        Some older Cisco SSH servers only support legacy algorithms (e.g.
        diffie-hellman-group14-sha1, hmac-sha1, ssh-rsa). Modern clients may
        refuse these by default, which can surface as SSHException/EOFError.

        We try a normal connect first, then auto-fallback to a "legacy" connect
        profile when we detect a likely algorithm mismatch.
        """

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self._dbg(
                "attempt=default "
                f"host={self.host} port={self.profile.port} user={self.profile.username} "
                f"timeouts(connect={self.profile.connect_timeout},banner={self.profile.banner_timeout},auth={self.profile.auth_timeout}) "
                "look_for_keys=False allow_agent=False"
            )
            ssh.connect(
                hostname=self.host,
                port=self.profile.port,
                username=self.profile.username,
                password=self.profile.password,
                look_for_keys=False,
                allow_agent=False,
                timeout=self.profile.connect_timeout,
                banner_timeout=self.profile.banner_timeout,
                auth_timeout=self.profile.auth_timeout,
            )
            return ssh
        except Exception as e:
            self._dbg(f"default_failed type={type(e).__name__} msg={e!r}")
            if self._looks_like_alg_mismatch(e):
                self._dbg("heuristic=alg_mismatch -> attempt=legacy")
                # Second attempt with explicit legacy algorithm allow-lists
                return self._connect_legacy()
            raise

    @staticmethod
    def _looks_like_alg_mismatch(err: Exception) -> bool:
        if isinstance(err, EOFError):
            return True
        msg = (str(err) or "").lower()
        needles = (
            "no matching",
            "unable to negotiate",
            "negotiat",
            "kex",
            "mac",
            "host key",
            "cipher",
            "incompatible",
        )
        if isinstance(err, SSHException):
            return any(n in msg for n in needles)
        return any(n in msg for n in needles)

    def _connect_legacy(self) -> paramiko.SSHClient:
        """Legacy algorithm fallback.

        Uses a raw Transport so we can *enable* older algorithms explicitly.
        Returns an SSHClient that is already connected.
        """

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        transport = paramiko.Transport((self.host, self.profile.port))
        transport.banner_timeout = self.profile.banner_timeout
        transport.auth_timeout = self.profile.auth_timeout

        opts = transport.get_security_options()

        legacy_kex = [
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group-exchange-sha1",
        ]
        legacy_macs = [
            "hmac-sha1",
            "hmac-sha1-96",
        ]
        legacy_ciphers = [
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
            "aes128-cbc",
            "aes256-cbc",
            "3des-cbc",
        ]
        legacy_keys = [
            "ssh-rsa",
        ]

        self._dbg(
            "attempt=legacy "
            f"host={self.host} port={self.profile.port} user={self.profile.username} "
            f"legacy_kex={legacy_kex} legacy_macs={legacy_macs} legacy_ciphers={legacy_ciphers} legacy_hostkeys={legacy_keys}"
        )

        def _prepend(existing: List[str], preferred: List[str]) -> List[str]:
            out: List[str] = []
            for x in preferred + list(existing or []):
                if x not in out:
                    out.append(x)
            return out

        # Paramiko 4 uses `digests` for MACs; older versions used `macs`.
        if hasattr(opts, "kex"):
            opts.kex = _prepend(getattr(opts, "kex", []), legacy_kex)
        if hasattr(opts, "digests"):
            opts.digests = _prepend(getattr(opts, "digests", []), legacy_macs)
        elif hasattr(opts, "macs"):
            opts.macs = _prepend(getattr(opts, "macs", []), legacy_macs)
        if hasattr(opts, "ciphers"):
            opts.ciphers = _prepend(getattr(opts, "ciphers", []), legacy_ciphers)
        if hasattr(opts, "key_types"):
            opts.key_types = _prepend(getattr(opts, "key_types", []), legacy_keys)

        # Echo the *effective* ordered preferences Paramiko will use.
        try:
            self._dbg(
                "legacy_effective "
                f"kex={getattr(opts, 'kex', None)} "
                f"digests={getattr(opts, 'digests', None) or getattr(opts, 'macs', None)} "
                f"ciphers={getattr(opts, 'ciphers', None)} "
                f"key_types={getattr(opts, 'key_types', None)}"
            )
        except Exception:
            pass

        transport.start_client(timeout=self.profile.connect_timeout)
        try:
            transport.auth_password(
                username=self.profile.username,
                password=self.profile.password,
                fallback=False,
            )
        except Exception as e:
            self._dbg(f"legacy_auth_failed type={type(e).__name__} msg={e!r}")
            raise

        # Bind the pre-connected transport to the SSHClient.
        ssh._transport = transport
        return ssh

    def connect(self) -> None:
        """Open a persistent SSH session (optional)."""
        if self._session is None:
            self._session = self._connect()

    def close(self) -> None:
        if self._session is not None:
            try:
                self._session.close()
            finally:
                self._session = None

    def exec(self, command: str) -> str:
        """Back-compat alias for exec_command."""
        return self.exec_command(command)

    def exec_command(self, command: str) -> str:
        ssh = self._session or self._connect()
        close_after = self._session is None
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=self.profile.command_timeout)
            out = stdout.read().decode(errors='ignore')
            err = stderr.read().decode(errors='ignore')
            return (out + ("\n" + err if err.strip() else "")).strip()
        finally:
            if close_after:
                ssh.close()

    def run_commands(self, commands: List[str], disable_paging: bool = True) -> Dict[str, str]:
        """Run multiple commands in a single interactive session.

        This is intentionally a bit "best-effort" and uses quiet-time based reads
        rather than full prompt-detection, because prompts vary across platforms.
        """
        ssh = self._connect()
        try:
            chan = ssh.invoke_shell(width=200, height=1000)
            chan.settimeout(self.profile.command_timeout)

            def _drain_quiet(quiet_s: float = 0.4, max_s: float = 6.0) -> str:
                buf = b""
                last = time.time()
                start = time.time()
                while True:
                    if time.time() - start > max_s:
                        break
                    try:
                        if chan.recv_ready():
                            chunk = chan.recv(65535)
                            if not chunk:
                                break
                            buf += chunk
                            last = time.time()
                        else:
                            time.sleep(0.05)
                            if time.time() - last >= quiet_s:
                                break
                    except Exception:
                        break
                return buf.decode(errors='ignore')

            # initial banner/prompt
            _drain_quiet()

            if disable_paging:
                # IOS/NX-OS commonly accept this
                chan.send("terminal length 0\n")
                _drain_quiet()

            results: Dict[str, str] = {}
            for cmd in commands:
                chan.send(cmd.strip() + "\n")
                out = _drain_quiet()
                results[cmd] = out
            return results
        finally:
            try:
                ssh.close()
            except Exception:
                pass


def load_ssh_profile_from_env() -> Optional[SshProfile]:
    user = os.getenv("ROLAND_SSH_USER") or os.getenv("SSH_USER")
    pw = os.getenv("ROLAND_SSH_PASS") or os.getenv("SSH_PASS")
    if not user or not pw:
        return None
    port = int(os.getenv("ROLAND_SSH_PORT", "22"))
    return SshProfile(username=user, password=pw, port=port)
