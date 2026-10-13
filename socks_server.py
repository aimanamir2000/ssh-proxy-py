"""
Minimal SOCKS5 server (RFC 1928) supporting the CONNECT command with
no authentication. Each accepted client connection is relayed through
a paramiko `direct-tcpip` channel obtained from an SSHTunnelManager,
so from the target's point of view, traffic originates from the
remote SSH server.
"""

import logging
import select
import socket
import socketserver
import struct

logger = logging.getLogger("ssh_proxy_py.socks")

SOCKS_VERSION = 5

# Reply codes (RFC 1928 section 6)
REP_SUCCEEDED = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_REFUSED = 0x05
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class SocksProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(30)

        try:
            self._handshake(client)
            dest_addr, dest_port = self._parse_request(client)
        except (ConnectionError, ValueError, socket.timeout) as exc:
            logger.debug("SOCKS negotiation failed from %s: %s", self.client_address, exc)
            client.close()
            return

        try:
            channel = self.server.ssh_tunnel_manager.open_channel(
                dest_addr, dest_port, self.client_address
            )
        except Exception as exc:
            logger.warning("Could not open SSH channel to %s:%s -> %s", dest_addr, dest_port, exc)
            self._send_reply(client, REP_CONNECTION_REFUSED)
            client.close()
            return

        self._send_reply(client, REP_SUCCEEDED)
        logger.info("Proxying %s -> %s:%s via SSH tunnel", self.client_address, dest_addr, dest_port)

        try:
            self._relay(client, channel)
        finally:
            channel.close()
            client.close()
            logger.debug("Closed %s -> %s:%s", self.client_address, dest_addr, dest_port)

    # -- SOCKS5 protocol handling -----------------------------------------

    def _handshake(self, client):
        header = self._recvn(client, 2)
        version, nmethods = header[0], header[1]
        if version != SOCKS_VERSION:
            raise ValueError(f"Unsupported SOCKS version: {version}")
        methods = self._recvn(client, nmethods)
        if 0x00 not in methods:  # only "no authentication required"
            client.sendall(bytes([SOCKS_VERSION, 0xFF]))
            raise ValueError("Client does not offer the 'no auth' method")
        client.sendall(bytes([SOCKS_VERSION, 0x00]))

    def _parse_request(self, client):
        header = self._recvn(client, 4)
        version, cmd, _reserved, atyp = header
        if version != SOCKS_VERSION:
            raise ValueError("Bad SOCKS version in request")
        if cmd != 0x01:  # only CONNECT supported
            self._send_reply(client, REP_COMMAND_NOT_SUPPORTED)
            raise ValueError(f"Unsupported SOCKS command: {cmd}")

        if atyp == 0x01:  # IPv4
            addr = socket.inet_ntoa(self._recvn(client, 4))
        elif atyp == 0x03:  # domain name
            length = self._recvn(client, 1)[0]
            raw_host = self._recvn(client, length)
            try:
                # Handles punycode-encoded (xn--...) international domains.
                addr = raw_host.decode("idna")
            except UnicodeError:
                # Plain ASCII hostnames (the vast majority of requests) that
                # the idna codec rejects for edge-case reasons -- fall back
                # to a plain decode instead of dropping the connection.
                addr = raw_host.decode("ascii", errors="ignore")
        elif atyp == 0x04:  # IPv6
            addr = socket.inet_ntop(socket.AF_INET6, self._recvn(client, 16))
        else:
            self._send_reply(client, REP_ADDRESS_TYPE_NOT_SUPPORTED)
            raise ValueError(f"Unsupported address type: {atyp}")

        port = struct.unpack("!H", self._recvn(client, 2))[0]
        return addr, port

    def _send_reply(self, client, rep_code, bind_addr=("0.0.0.0", 0)):
        host, port = bind_addr
        reply = struct.pack("!BBBB", SOCKS_VERSION, rep_code, 0x00, 0x01)
        reply += socket.inet_aton(host)
        reply += struct.pack("!H", port)
        try:
            client.sendall(reply)
        except OSError:
            pass

    @staticmethod
    def _recvn(sock, n):
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Client closed the connection")
            data += chunk
        return data

    # -- data relay ---------------------------------------------------------

    def _relay(self, client, channel):
        """Bidirectionally pump bytes between the client socket and the SSH channel."""
        client.setblocking(False)
        channel.setblocking(False)
        sockets = [client, channel]

        while True:
            try:
                readable, _, errored = select.select(sockets, [], sockets, 60)
            except (OSError, ValueError):
                break

            if errored:
                break
            if not readable:
                break  # idle timeout

            try:
                if client in readable:
                    data = client.recv(4096)
                    if not data:
                        break
                    channel.sendall(data)
                if channel in readable:
                    data = channel.recv(4096)
                    if not data:
                        break
                    client.sendall(data)
            except (ConnectionResetError, OSError):
                break


class ThreadingSocksServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, ssh_tunnel_manager):
        self.ssh_tunnel_manager = ssh_tunnel_manager
        super().__init__(server_address, SocksProxyHandler)
