# SSH Proxy Py

A local SOCKS5 proxy server that forwards every connection through an SSH
server reached via `cloudflared` (Cloudflare Access SSH). Point any
SOCKS5-aware client/app at the local listener, and remote destinations
will see the SSH server's IP address as the source of the traffic --
the same effect as `ssh -D 1080 user@host`, but running as a standalone
Python service instead of a live `ssh` session.

```
[Your app] --SOCKS5--> 127.0.0.1:1080 --(this proxy)--> paramiko SSH session
                                                            (tunneled through
                                                             `cloudflared access ssh`)
                                                                  |
                                                                  v
                                                          Server B (SSH host)
                                                                  |
                                                                  v
                                                          Destination sees
                                                          Server B's IP
```

## How it works

1. On startup, the app spawns `cloudflared access ssh --hostname <hostname>`
   as an SSH `ProxyCommand` (via `paramiko.ProxyCommand`), which tunnels a
   raw SSH byte stream to Server B through Cloudflare Access.
2. `paramiko` performs the SSH handshake and authenticates with a
   username/password over that tunnel.
3. A threaded SOCKS5 server listens locally. For every client connection,
   it asks the SSH session to open a `direct-tcpip` channel to the
   requested destination -- exactly what `ssh -D` does under the hood --
   and relays bytes in both directions.

## Requirements

- Python 3.9+
- The [`cloudflared`](https://github.com/cloudflare/cloudflared) binary
  on your `PATH` (or point `cloudflared_binary` at its location), already
  configured for Cloudflare Access SSH to Server B (i.e. `cloudflared
  access ssh --hostname <hostname>` works on its own from your shell).
- An SSH user/password on Server B.

## Install

```bash
cd ssh_proxy_py
pip install -r requirements.txt
```

## Configure

Copy the example config and fill in your values:

```bash
cp config.example.yaml config.yaml
```

```yaml
cloudflared_hostname: ssh.example.com   # (1) hostname in your Cloudflare Access SSH app
cloudflared_binary: cloudflared

listen_host: 127.0.0.1                  # (2) local SOCKS5 listen address/port
listen_port: 1080

ssh_username: myuser                    # (3) SSH login on Server B
ssh_password: "mypassword"

strict_host_key_checking: false
known_hosts_path: ""
log_level: INFO
```

All three configurable groups the app needs:

| # | Setting | Purpose |
|---|---------|---------|
| 1 | `cloudflared_hostname` | The Cloudflare Access SSH hostname for Server B |
| 2 | `listen_host` / `listen_port` | Where the local SOCKS5 proxy listens |
| 3 | `ssh_username` / `ssh_password` | SSH login on Server B |

Every setting can also be passed as a CLI flag or an environment variable,
which is handy for keeping the password out of a file:

```bash
export SSH_PROXY_SSH_PASSWORD='mypassword'
python main.py --config config.yaml
```

```bash
python main.py \
  --cloudflared-hostname ssh.example.com \
  --listen-host 127.0.0.1 --listen-port 1080 \
  --ssh-username myuser --ssh-password "$SSH_PROXY_SSH_PASSWORD"
```

Precedence: **CLI flags > environment variables > YAML file > defaults**.

## Run

```bash
python main.py --config config.yaml
```

You should see:

```
INFO ssh_proxy_py.main: Connecting to SSH server via cloudflared (ssh.example.com)...
INFO ssh_proxy_py.ssh_tunnel: SSH session established via cloudflared to 'ssh.example.com' as user 'myuser'
INFO ssh_proxy_py.main: SOCKS5 proxy listening on 127.0.0.1:1080
```

## Use it

Point any SOCKS5 client at `127.0.0.1:1080`. For example, to make a curl
request appear to come from Server B:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

(`socks5h` resolves the hostname on the remote side too, which matters
since DNS should also happen from Server B's vantage point, not yours.)

## Security notes

- By default the app **does not verify the SSH host key** presented over
  the cloudflared tunnel (`strict_host_key_checking: false`), because the
  key seen through the ProxyCommand may not match what's in a normal
  `~/.ssh/known_hosts`. This is fine for a quick test but means a
  compromised Cloudflare Access edge or SSH host could go undetected.
  For anything beyond local testing, set:
  ```yaml
  strict_host_key_checking: true
  known_hosts_path: /path/to/known_hosts
  ```
  and pre-populate that file with Server B's real host key fingerprint.
- Prefer SSH key-based auth over passwords where possible; this build
  supports password auth per your requirements, but the codebase
  (`ssh_tunnel.py`) is a natural place to add `transport.auth_publickey()`
  if you'd rather use a private key.
- The SOCKS5 listener has no authentication of its own and accepts
  `CONNECT` from anything that can reach `listen_host:listen_port`.
  Keep `listen_host` bound to `127.0.0.1` (the default) unless you add
  your own network-level access control (firewall, VPN, etc.) around it.
- Don't commit `config.yaml` with a real password in it; use the env var
  or CLI flag instead, or `chmod 600 config.yaml`.

## Project layout

```
ssh_proxy_py/
├── main.py               # entry point, wiring, signal handling
├── config.py             # YAML/CLI/env config loading
├── ssh_tunnel.py         # paramiko SSH session over cloudflared ProxyCommand
├── socks_server.py       # threaded SOCKS5 (RFC 1928) server, CONNECT only
├── requirements.txt
├── config.example.yaml
└── README.md
```

## Limitations

- Only the SOCKS5 `CONNECT` command is implemented (no `BIND` or
  `UDP ASSOCIATE`) -- this covers essentially all normal TCP client usage
  (browsers, curl, most CLI tools).
- No SOCKS5 username/password auth on the listener itself (see security
  notes above).
- A single shared SSH session is reused for all client connections and
  is transparently re-established if it drops.
