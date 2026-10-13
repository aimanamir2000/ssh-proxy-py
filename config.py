"""
Configuration loading for SSH Proxy Py.

Precedence (highest wins): CLI flags > environment variables > YAML config file > defaults.
"""

import argparse
import dataclasses
import os
from pathlib import Path

import yaml


@dataclasses.dataclass
class Config:
    # Required
    cloudflared_hostname: str      # Hostname registered in Cloudflare Access for SSH
    ssh_username: str
    ssh_password: str

    # Optional
    listen_host: str = "127.0.0.1"
    listen_port: int = 1080
    cloudflared_binary: str = "cloudflared"
    strict_host_key_checking: bool = False
    known_hosts_path: str = ""
    log_level: str = "INFO"


def _load_yaml(path):
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with p.open("r") as f:
        return yaml.safe_load(f) or {}


def load_config(argv=None):
    parser = argparse.ArgumentParser(
        prog="ssh-proxy-py",
        description="SOCKS5 proxy that forwards traffic through an SSH server reached via cloudflared.",
    )
    parser.add_argument("-c", "--config", help="Path to YAML config file")
    parser.add_argument("--cloudflared-hostname", help="Hostname configured in Cloudflare Access for SSH")
    parser.add_argument("--cloudflared-binary", help="Path to the cloudflared binary (default: cloudflared)")
    parser.add_argument("--listen-host", help="Local address the SOCKS5 proxy listens on")
    parser.add_argument("--listen-port", type=int, help="Local port the SOCKS5 proxy listens on")
    parser.add_argument("--ssh-username", help="SSH username")
    parser.add_argument("--ssh-password", help="SSH password")
    parser.add_argument(
        "--strict-host-key-checking",
        action="store_true",
        default=None,
        help="Verify the SSH host key against --known-hosts-path instead of trusting it blindly",
    )
    parser.add_argument("--known-hosts-path", help="Path to a known_hosts file used for host key pinning")
    parser.add_argument("--log-level", help="DEBUG, INFO, WARNING, ERROR")
    args = parser.parse_args(argv)

    file_values = _load_yaml(args.config)

    # Environment variable fallbacks -- handy for containers / secret managers,
    # so passwords don't have to sit in a config file or shell history.
    env_values = {
        "cloudflared_hostname": os.environ.get("SSH_PROXY_CLOUDFLARED_HOSTNAME"),
        "cloudflared_binary": os.environ.get("SSH_PROXY_CLOUDFLARED_BINARY"),
        "listen_host": os.environ.get("SSH_PROXY_LISTEN_HOST"),
        "listen_port": os.environ.get("SSH_PROXY_LISTEN_PORT"),
        "ssh_username": os.environ.get("SSH_PROXY_SSH_USERNAME"),
        "ssh_password": os.environ.get("SSH_PROXY_SSH_PASSWORD"),
        "log_level": os.environ.get("SSH_PROXY_LOG_LEVEL"),
    }
    if env_values.get("listen_port") is not None:
        env_values["listen_port"] = int(env_values["listen_port"])
    env_values = {k: v for k, v in env_values.items() if v is not None}

    cli_values = {
        "cloudflared_hostname": args.cloudflared_hostname,
        "cloudflared_binary": args.cloudflared_binary,
        "listen_host": args.listen_host,
        "listen_port": args.listen_port,
        "ssh_username": args.ssh_username,
        "ssh_password": args.ssh_password,
        "strict_host_key_checking": args.strict_host_key_checking,
        "known_hosts_path": args.known_hosts_path,
        "log_level": args.log_level,
    }
    cli_values = {k: v for k, v in cli_values.items() if v is not None}

    merged = {}
    merged.update(file_values)
    merged.update(env_values)
    merged.update(cli_values)

    missing = [
        field
        for field in ("cloudflared_hostname", "ssh_username", "ssh_password")
        if not merged.get(field)
    ]
    if missing:
        parser.error(
            "Missing required setting(s): "
            + ", ".join(missing)
            + ". Provide them via --config file, CLI flags, or environment variables "
            + "(SSH_PROXY_CLOUDFLARED_HOSTNAME / SSH_PROXY_SSH_USERNAME / SSH_PROXY_SSH_PASSWORD)."
        )

    known_fields = {f.name for f in dataclasses.fields(Config)}
    filtered = {k: v for k, v in merged.items() if k in known_fields}

    return Config(**filtered)
