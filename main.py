#!/usr/bin/env python3
"""
SSH Proxy Py
============

A local SOCKS5 proxy that forwards all traffic through an SSH server
reached via `cloudflared` (Cloudflare Access SSH). Point any SOCKS5-aware
client/app at the local listener, and remote destinations will see the
SSH server's IP address as the source of the traffic -- the same effect
as `ssh -D`, but running as its own standalone Python service.

Usage:
    python main.py --config config.yaml
    python main.py --cloudflared-hostname ssh.example.com --ssh-username bob --ssh-password secret

See config.example.yaml and README.md for all options.
"""

import logging
import signal
import sys

from config import load_config
from ssh_tunnel import SSHTunnelManager
from socks_server import ThreadingSocksServer


def main():
    config = load_config()

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    logger = logging.getLogger("ssh_proxy_py.main")

    tunnel = SSHTunnelManager(config)
    logger.info("Connecting to SSH server via cloudflared (%s)...", config.cloudflared_hostname)
    try:
        tunnel.connect()
    except Exception as exc:
        logger.error("Failed to establish SSH tunnel: %s", exc)
        sys.exit(1)

    server = ThreadingSocksServer((config.listen_host, config.listen_port), tunnel)
    logger.info("SOCKS5 proxy listening on %s:%s", config.listen_host, config.listen_port)
    logger.info("All connections through this proxy will be sourced from the remote SSH server.")

    def shutdown(signum, frame):
        logger.info("Shutting down...")
        threading_stop(server, tunnel)
        sys.exit(0)

    def threading_stop(server, tunnel):
        # server.shutdown() from within a signal handler can deadlock the
        # serve_forever() loop on some platforms, so do it from a thread.
        import threading

        def _stop():
            server.shutdown()
            server.server_close()
            tunnel.close()

        threading.Thread(target=_stop, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    finally:
        tunnel.close()


if __name__ == "__main__":
    main()
