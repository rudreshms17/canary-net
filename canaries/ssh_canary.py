"""
SSH Honeypot Canary
Fake SSH server that logs and alerts on connection attempts
"""

import logging
import re
import socket
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict

from .base_canary import BaseCanary

logger = logging.getLogger(__name__)


class SSHCanary(BaseCanary):
    """
    SSH Honeypot Service.

    Presents a lightweight fake SSH server that captures connection probes
    with a plain TCP socket, avoiding Paramiko negotiation issues on Windows.
    """

    def __init__(
        self,
        port: int,
        name: str,
        fake_data: dict,
        alert_callback: Callable[[Dict[str, Any]], None]
    ):
        """Initialize SSH Canary."""
        super().__init__(port, name, fake_data, alert_callback)
        self.listen_socket = None
        self.server_thread = None

    def start(self):
        """Start the SSH honeypot server."""
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind(("0.0.0.0", self.port))
            self.listen_socket.listen(5)
            self.listen_socket.settimeout(1)

            self.running = True

            self.server_thread = threading.Thread(
                target=self._accept_connections,
                daemon=True
            )
            self.server_thread.start()

            logger.info(
                f"[{self.name}] SSH Honeypot started on 0.0.0.0:{self.port} "
                f"with banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6'"
            )

        except Exception as e:
            logger.error(f"[{self.name}] Failed to start SSH server: {e}", exc_info=True)
            self.running = False

    def _accept_connections(self):
        """Accept incoming SSH connections."""
        while self.running:
            try:
                client_socket, addr = self.listen_socket.accept()
                client_ip, client_port = addr

                handler_thread = threading.Thread(
                    target=self._handle_ssh_connection,
                    args=(client_socket, client_ip, client_port),
                    daemon=True
                )
                handler_thread.start()

            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                if self.running:
                    logger.error(f"[{self.name}] Error accepting connection: {e}")

    def _extract_username(self, raw_data: bytes) -> str:
        """Try to infer a username from the raw client data."""
        if not raw_data:
            return "unknown"

        try:
            text = raw_data.decode("utf-8", errors="ignore")
        except Exception:
            text = ""

        if not text:
            return "unknown"

        match = re.search(r"\b(user(?:name)?|root|admin|guest|oracle|postgres|administrator)\b", text, re.IGNORECASE)
        if match:
            return match.group(1).lower()

        return "unknown"

    def _fire_alert(self, client_ip: str, client_port: int, username: str, raw_data: bytes):
        """Fire the alert using the existing callback path."""
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "") + "Z"
        alert = {
            "canary_name": self.name,
            "port": self.port,
            "attacker_ip": client_ip,
            "attacker_port": client_port,
            "behavior": "ssh_connection_attempt",
            "username": username,
            "raw_data": raw_data[:100].hex(),
            "timestamp": timestamp,
            "fake_data_touched": False,
        }

        logger.warning(
            f"[SSH] Connection attempt: {client_ip}:{client_port} "
            f"username={username}"
        )
        self.alert_callback(alert)

    def _handle_ssh_connection(self, client_socket: socket.socket, client_ip: str, client_port: int):
        """Handle an individual SSH connection attempt."""
        banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

        try:
            client_socket.settimeout(3)
            client_socket.sendall(banner)

            client_data = client_socket.recv(512)
            username = self._extract_username(client_data)
            self._fire_alert(client_ip, client_port, username, client_data)

        except socket.timeout:
            logger.debug(f"[{self.name}] Connection timeout from {client_ip}:{client_port}")
        except OSError as e:
            logger.debug(f"[{self.name}] Socket error from {client_ip}:{client_port}: {e}")
        except Exception as e:
            logger.debug(f"[{self.name}] Error handling SSH connection: {e}")
        finally:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            except Exception:
                pass
            finally:
                try:
                    client_socket.close()
                except Exception:
                    pass

    def stop(self):
        """Stop the SSH honeypot server."""
        try:
            self.running = False

            if self.listen_socket:
                self.listen_socket.close()

            logger.info(f"[{self.name}] SSH Honeypot stopped")

        except Exception as e:
            logger.error(f"[{self.name}] Error stopping SSH server: {e}", exc_info=True)
