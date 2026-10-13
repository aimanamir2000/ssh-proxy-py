"""
Owns a single SSH connection that is established *through* `cloudflared`
(used the same way you'd use it as an SSH ProxyCommand), and hands out
direct-tcpip channels for the SOCKS server to relay traffic through.

This is the programmatic equivalent of:

    ssh -o ProxyCommand="cloudflared access ssh --hostname <host>" \
        -D 1080 user@<host>

but implemented with paramiko so it can run as a standalone service.
"""

import logging
import threading

import paramiko

logger = logging.getLogger("ssh_proxy_py.ssh_tunnel")


class SSHTunnelManager:
    def __init__(self, config):
        self.config = config
        self._transport = None
        self._proxy = None
        self._lock = threading.RLock()

    # -- public API -----------------------------------------------------

    def connect(self):
        with self._lock:
            self._connect_locked()

    def open_channel(self, dest_addr, dest_port, src_addr):
        """
        Open a direct-tcpip channel to (dest_addr, dest_port) as seen from
        the remote SSH server. src_addr is the (host, port) tuple of the
        local SOCKS client, purely informational for the SSH server logs.
        """
        with self._lock:
            self._ensure_connected()
            transport = self._transport

        try:
            channel = transport.open_channel(
                "direct-tcpip", (dest_addr, dest_port), src_addr, timeout=30
            )
        except Exception as exc:
            logger.warning("Channel open failed (%s), retrying with a fresh SSH session", exc)
            with self._lock:
                self._connect_locked()
                transport = self._transport
            channel = transport.open_channel(
                "direct-tcpip", (dest_addr, dest_port), src_addr, timeout=30
            )

        if channel is None:
            raise RuntimeError(
                f"SSH server refused to open a channel to {dest_addr}:{dest_port} "
                "(destination unreachable or blocked by the SSH server's policy)"
            )
        return channel

    def close(self):
        with self._lock:
            if self._transport is not None:
                try:
                    self._transport.close()
                except Exception:
                    pass
                self._transport = None
            if self._proxy is not None:
                try:
                    self._proxy.close()
                except Exception:
                    pass
                self._proxy = None

    # -- internals --------------------------------------------------------

    def _connect_locked(self):
        cfg = self.config

        # Tear down any half-dead previous session first.
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                pass
        if self._proxy is not None:
            try:
                self._proxy.close()
            except Exception:
                pass

        proxy_cmd = f"{cfg.cloudflared_binary} access ssh --hostname {cfg.cloudflared_hostname}"
        logger.info("Launching cloudflared as SSH ProxyCommand: %s", proxy_cmd)
        proxy = paramiko.ProxyCommand(proxy_cmd)

        transport = paramiko.Transport(proxy)
        transport.set_keepalive(30)
        try:
            transport.start_client(timeout=30)

            if cfg.strict_host_key_checking:
                self._verify_host_key(transport)
            else:
                logger.warning(
                    "strict_host_key_checking is disabled -- the SSH host key is NOT being "
                    "verified. Set strict_host_key_checking + known_hosts_path for production use."
                )

            transport.auth_password(cfg.ssh_username, cfg.ssh_password)
            if not transport.is_authenticated():
                raise RuntimeError("SSH authentication failed (bad username/password?)")
        except Exception:
            transport.close()
            proxy.close()
            raise

        self._transport = transport
        self._proxy = proxy
        logger.info(
            "SSH session established via cloudflared to '%s' as user '%s'",
            cfg.cloudflared_hostname,
            cfg.ssh_username,
        )

    def _ensure_connected(self):
        if self._transport is not None and self._transport.is_active():
            return
        logger.info("SSH transport is not active, (re)connecting via cloudflared...")
        self._connect_locked()

    def _verify_host_key(self, transport):
        cfg = self.config
        key = transport.get_remote_server_key()

        if not cfg.known_hosts_path:
            logger.warning(
                "strict_host_key_checking is enabled but known_hosts_path is empty; "
                "cannot verify the host key. Refusing to connect."
            )
            raise RuntimeError("known_hosts_path must be set when strict_host_key_checking is true")

        keys = paramiko.hostkeys.HostKeys()
        try:
            keys.load(cfg.known_hosts_path)
        except FileNotFoundError:
            raise RuntimeError(f"known_hosts_path '{cfg.known_hosts_path}' does not exist")

        if not keys.check(cfg.cloudflared_hostname, key):
            raise RuntimeError(
                f"Host key for '{cfg.cloudflared_hostname}' does not match the entry in "
                f"{cfg.known_hosts_path}. Refusing to connect (possible MITM)."
            )
        logger.info("SSH host key for '%s' verified against known_hosts", cfg.cloudflared_hostname)
