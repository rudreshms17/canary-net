"""
SMB Honeypot Canary
Fake SMB server that logs and alerts on file sharing attacks
"""

import logging
from typing import Callable, Dict, Any
import threading
import socket
import struct
from .base_canary import BaseCanary

logger = logging.getLogger(__name__)


# SMB Protocol Constants
SMB_HEADER_SIZE = 32
SMB_SIGNATURE = b'\xFF\x53\x4D\x42'  # 0xFF, 'S', 'M', 'B'

# SMB Command Codes
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73

# SMB Flags
SMB_FLAGS_RESPONSE = 0x80


class SMBPacketParser:
    """
    SMB Packet Parser and Builder
    
    SMB (Server Message Block) Packet Structure:
    ============================================
    
    SMB Header (32 bytes):
    - Signature (4 bytes):     0xFF, 'S', 'M', 'B'
    - Command (1 byte):        0x72 (NEGOTIATE), 0x73 (SESSION_SETUP), etc.
    - Status (4 bytes):        Error code
    - Flags (1 byte):          0x80 = Response, 0x08 = Caseless, 0x01 = Lock & Read
    - Flags2 (2 bytes):        Extended attributes, Unicode, NT Status, etc.
    - Process ID High (2 bytes)
    - Signature (8 bytes):     Security signature
    - Reserved (2 bytes)
    - Tree ID (2 bytes):       SMBID of share (0xFFFF for negotiation)
    - Process ID (2 bytes)
    - User ID (2 bytes)
    - Multiplex ID (2 bytes)
    
    Command Payload (variable):
    Followed by the specific command data
    
    NEGOTIATE Command:
    - Word Count (1 byte):     Number of 16-bit words in parameter block
    - Byte Count (2 bytes):    Size of data block
    - Dialect list:            Null-terminated strings of supported dialects
    
    SESSION_SETUP_ANDX Command:
    - Word Count (1 byte)
    - Account (domain\\username)
    - Password
    - OS string
    - LAN Manager version
    """
    
    @staticmethod
    def parse_smb_header(data: bytes) -> Dict[str, Any]:
        """
        Parse SMB header from packet
        
        Args:
            data: Raw packet bytes
            
        Returns:
            Dictionary with parsed header fields
        """
        if len(data) < SMB_HEADER_SIZE:
            return None
        
        header = {
            'signature': data[0:4],
            'command': data[4],
            'status': struct.unpack('<I', data[5:9])[0],
            'flags': data[9],
            'flags2': struct.unpack('<H', data[10:12])[0],
            'pid_high': struct.unpack('<H', data[12:14])[0],
            'signature_seq': data[14:22],
            'reserved': struct.unpack('<H', data[22:24])[0],
            'tree_id': struct.unpack('<H', data[24:26])[0],
            'process_id': struct.unpack('<H', data[26:28])[0],
            'user_id': struct.unpack('<H', data[28:30])[0],
            'multiplex_id': struct.unpack('<H', data[30:32])[0],
        }
        return header
    
    @staticmethod
    def build_negotiate_response(client_guid: bytes = None) -> bytes:
        """
        Build SMB NEGOTIATE response packet
        
        Args:
            client_guid: Optional GUID for the server
            
        Returns:
            Complete SMB NEGOTIATE response
        """
        if client_guid is None:
            client_guid = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        
        # Build response header
        header = bytearray(SMB_HEADER_SIZE)
        header[0:4] = SMB_SIGNATURE
        header[4] = SMB_COM_NEGOTIATE
        header[9] = SMB_FLAGS_RESPONSE
        header[10:12] = struct.pack('<H', 0xC353)  # Flags2
        header[24:26] = struct.pack('<H', 0xFFFF)  # Tree ID
        header[26:28] = struct.pack('<H', 0x0000)  # Process ID
        header[28:30] = struct.pack('<H', 0x0000)  # User ID
        header[30:32] = struct.pack('<H', 0x0000)  # Multiplex ID
        
        # Build negotiate response body
        word_count = 17
        parameter_block = struct.pack('<B', word_count)
        parameter_block += struct.pack('<H', 0)  # Dialect index
        parameter_block += struct.pack('<B', 0x03)  # Security mode
        parameter_block += struct.pack('<H', 8192)  # Max buffer size
        parameter_block += struct.pack('<H', 1)  # Max MUX count
        parameter_block += struct.pack('<H', 0)  # Virtual circuits
        parameter_block += struct.pack('<I', 0)  # Session key
        parameter_block += struct.pack('<I', 0x00000001)  # Capabilities
        parameter_block += struct.pack('<I', 0)  # System time low
        parameter_block += struct.pack('<I', 0)  # System time high
        parameter_block += struct.pack('<H', 0)  # Server timezone
        parameter_block += struct.pack('<B', 0)  # Encryption key length
        parameter_block += struct.pack('<H', 0)  # Byte count
        
        return bytes(header + parameter_block)
    
    @staticmethod
    def extract_credentials(data: bytes, offset: int = SMB_HEADER_SIZE) -> Dict[str, str]:
        """
        Extract credentials from SESSION_SETUP_ANDX request
        
        Args:
            data: Raw packet bytes
            offset: Offset to command payload
            
        Returns:
            Dictionary with extracted credentials
        """
        credentials = {
            'domain': '',
            'username': '',
            'password': '',
            'os': ''
        }
        
        try:
            if len(data) <= offset:
                return credentials
            
            # Skip Word Count (1 byte) and AndXOffset (1 byte)
            if len(data) <= offset + 2:
                return credentials
            
            pos = offset + 2
            
            # Parse account (domain\username)
            if len(data) > pos + 2:
                acct_offset = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
            
            # Look for null-terminated strings in the remaining data
            remaining = data[pos:]
            strings = remaining.split(b'\x00')
            
            if len(strings) >= 1:
                # First string is usually domain\username
                acct_str = strings[0].decode('utf-16-le', errors='ignore')
                if '\\' in acct_str:
                    parts = acct_str.split('\\')
                    credentials['domain'] = parts[0]
                    credentials['username'] = parts[1] if len(parts) > 1 else parts[0]
                else:
                    credentials['username'] = acct_str
            
            if len(strings) >= 2:
                credentials['os'] = strings[1].decode('utf-16-le', errors='ignore')
            
            if len(strings) >= 3:
                credentials['password'] = strings[2].decode('utf-16-le', errors='ignore')
        
        except Exception as e:
            logger.debug(f"Error extracting credentials: {e}")
        
        return credentials


class SMBCanary(BaseCanary):
    """
    SMB Honeypot Service
    
    Presents a fake SMB file server that captures file sharing attacks,
    including credential harvesting and network reconnaissance.
    """
    
    def __init__(
        self,
        port: int,
        name: str,
        fake_data: dict,
        alert_callback: Callable[[Dict[str, Any]], None]
    ):
        """
        Initialize SMB Canary
        
        Args:
            port: Port to listen on (typically 445)
            name: Canary name
            fake_data: Fake data dictionary
            alert_callback: Alert callback function
        """
        super().__init__(port, name, fake_data, alert_callback)
        self.listen_socket = None
        self.server_thread = None
    
    def start(self):
        """Start the SMB honeypot server"""
        try:
            # Create listening socket
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind(('0.0.0.0', self.port))
            self.listen_socket.listen(5)
            
            self.running = True
            
            # Start server thread
            self.server_thread = threading.Thread(
                target=self._accept_connections,
                daemon=True
            )
            self.server_thread.start()
            
            logger.info(
                f"[{self.name}] SMB Honeypot started on 0.0.0.0:{self.port}"
            )
        
        except Exception as e:
            logger.error(f"[{self.name}] Failed to start SMB server: {e}", exc_info=True)
            self.running = False
    
    def _accept_connections(self):
        """Accept and handle incoming SMB connections"""
        while self.running:
            try:
                # Set timeout to allow clean shutdown
                self.listen_socket.settimeout(1)
                
                # Accept incoming connection
                client_socket, addr = self.listen_socket.accept()
                client_ip, client_port = addr
                
                # Handle connection in a separate thread
                handler_thread = threading.Thread(
                    target=self._handle_smb_connection,
                    args=(client_socket, client_ip, client_port),
                    daemon=True
                )
                handler_thread.start()
            
            except socket.timeout:
                continue
            except OSError:
                # Socket closed
                break
            except Exception as e:
                if self.running:
                    logger.error(f"[{self.name}] Error accepting connection: {e}")
    
    def _handle_smb_connection(self, client_socket: socket.socket, client_ip: str, client_port: int):
        """
        Handle individual SMB connection
        
        Args:
            client_socket: Connected socket
            client_ip: Client IP address
            client_port: Client port
        """
        try:
            client_socket.settimeout(5)
            
            # Receive SMB NEGOTIATE request
            data = client_socket.recv(4096)
            
            if not data or len(data) < SMB_HEADER_SIZE:
                return
            
            # Verify SMB signature
            if data[0:4] != SMB_SIGNATURE:
                logger.debug(f"[{self.name}] Invalid SMB signature from {client_ip}")
                return
            
            # Parse header
            header = SMBPacketParser.parse_smb_header(data)
            if not header:
                return
            
            command = header['command']
            logger.debug(f"[{self.name}] SMB command {hex(command)} from {client_ip}:{client_port}")
            
            # Handle NEGOTIATE request
            if command == SMB_COM_NEGOTIATE:
                self._handle_negotiate(client_socket, client_ip, client_port)
            
        except socket.timeout:
            logger.debug(f"[{self.name}] Connection timeout from {client_ip}:{client_port}")
        except Exception as e:
            logger.debug(f"[{self.name}] Error handling SMB connection: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_negotiate(self, client_socket: socket.socket, client_ip: str, client_port: int):
        """
        Handle SMB NEGOTIATE request and wait for SESSION_SETUP
        
        Args:
            client_socket: Connected socket
            client_ip: Client IP address
            client_port: Client port
        """
        try:
            # Send NEGOTIATE response
            negotiate_response = SMBPacketParser.build_negotiate_response()
            client_socket.sendall(negotiate_response)
            
            # Wait for SESSION_SETUP request
            data = client_socket.recv(4096)
            
            if len(data) < SMB_HEADER_SIZE:
                return
            
            # Parse header
            header = SMBPacketParser.parse_smb_header(data)
            if not header:
                return
            
            command = header['command']
            
            # Handle SESSION_SETUP_ANDX
            if command == SMB_COM_SESSION_SETUP_ANDX:
                credentials = SMBPacketParser.extract_credentials(data)
                
                behavior_msg = (
                    f"smb_session_setup: "
                    f"domain={credentials['domain']} "
                    f"username={credentials['username']} "
                    f"os={credentials['os']}"
                )
                
                self._trigger_alert(
                    attacker_ip=client_ip,
                    attacker_port=client_port,
                    behavior=behavior_msg,
                    fake_data_touched=True
                )
                
                logger.warning(
                    f"[SMB] Session setup from {client_ip}:{client_port} | "
                    f"Domain: {credentials['domain']} | "
                    f"User: {credentials['username']} | "
                    f"OS: {credentials['os']}"
                )
        
        except Exception as e:
            logger.debug(f"[{self.name}] Error in negotiate handler: {e}")
    
    def stop(self):
        """Stop the SMB honeypot server"""
        try:
            self.running = False
            
            if self.listen_socket:
                self.listen_socket.close()
            
            logger.info(f"[{self.name}] SMB Honeypot stopped")
        
        except Exception as e:
            logger.error(f"[{self.name}] Error stopping SMB server: {e}", exc_info=True)
