"""
HTTP Honeypot Canary
Fake web server that logs and alerts on web requests
"""

import logging
from typing import Callable, Dict, Any
import threading
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from .base_canary import BaseCanary

logger = logging.getLogger(__name__)


class HTTPRequestHandler(BaseHTTPRequestHandler):
    """Custom HTTP request handler for honeypot"""
    
    # Class variable to store reference to the canary instance
    canary_instance = None
    
    def log_message(self, format, *args):
        """Override to suppress default logging (we handle it)"""
        pass
    
    def do_GET(self):
        """Handle GET requests"""
        self._handle_request('GET', None)
    
    def do_POST(self):
        """Handle POST requests"""
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        self._handle_request('POST', body)
    
    def _handle_request(self, method: str, body: str = None):
        """
        Handle incoming HTTP request
        
        Args:
            method: HTTP method (GET, POST, etc.)
            body: Request body (for POST requests)
        """
        # Parse request
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_string = parsed_url.query
        
        # Extract key headers
        user_agent = self.headers.get('User-Agent', 'Unknown')
        authorization = self.headers.get('Authorization', '')
        content_type = self.headers.get('Content-Type', '')
        host = self.headers.get('Host', '')
        
        # Get client info
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        
        # Build behavior description
        behavior_parts = [
            f"http_{method.lower()}_request",
            f"path={path}",
            f"user_agent={user_agent}"
        ]
        
        if authorization:
            behavior_parts.append(f"auth={authorization[:50]}")  # Truncate for brevity
        
        if body:
            behavior_parts.append(f"body_size={len(body)}")
        
        behavior = " | ".join(behavior_parts)
        
        # Trigger alert
        if self.canary_instance:
            self.canary_instance._trigger_alert(
                attacker_ip=client_ip,
                attacker_port=client_port,
                behavior=behavior,
                fake_data_touched=(path.startswith('/api') or path == '/admin')
            )
        
        logger.warning(
            f"[HTTP] {method} {path} from {client_ip}:{client_port} | "
            f"User-Agent: {user_agent} | Auth: {bool(authorization)}"
        )
        
        # Route request to appropriate handler
        if path == '/admin':
            self._serve_admin_login()
        elif path == '/api/v1/status':
            self._serve_api_status()
        elif path == '/api/v1/keys':
            self._serve_api_keys()
        else:
            self._serve_404()
    
    def _serve_admin_login(self):
        """Serve fake admin login page"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Admin Login - Server Management</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
            font-size: 24px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .error-message {
            color: #dc3545;
            font-size: 14px;
            margin-top: 15px;
            text-align: center;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Admin Panel</h1>
        <form method="POST" action="/admin">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit">Sign In</button>
            <div class="error-message" id="error">Invalid credentials</div>
        </form>
    </div>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Server', 'Apache/2.4.52 (Ubuntu)')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def _serve_api_status(self):
        """Serve fake API status endpoint"""
        response_data = {
            "status": "operational",
            "version": "2.1.4",
            "uptime_seconds": 2592000,
            "database": {
                "status": "connected",
                "size_mb": 4821.5,
                "queries_per_sec": 342
            },
            "memory": {
                "used_mb": 2048,
                "available_mb": 6144,
                "utilization_percent": 33.3
            },
            "services": [
                {"name": "auth-service", "status": "healthy", "response_time_ms": 12},
                {"name": "data-service", "status": "healthy", "response_time_ms": 45},
                {"name": "notification-service", "status": "degraded", "response_time_ms": 250}
            ],
            "last_deployment": "2024-05-15T14:32:00Z",
            "environment": "production"
        }
        
        response_json = json.dumps(response_data, indent=2)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Server', 'nginx/1.25.1')
        self.send_header('X-API-Version', 'v1')
        self.end_headers()
        self.wfile.write(response_json.encode('utf-8'))
    
    def _serve_api_keys(self):
        """Serve fake API keys endpoint"""
        response_data = {
            "api_keys": [
                {
                    "id": "key_prod_1a2b3c4d5e6f",
                    "name": "Production API Key",
                    "secret": "sk_FAKE_CANARY_TOKEN_NOT_REAL_xxxx1234",
                    "created": "2024-01-15T09:30:00Z",
                    "last_used": "2024-06-08T14:22:15Z",
                    "scopes": ["read", "write", "delete"],
                    "active": True
                },
                {
                    "id": "key_staging_7h8i9j0k1l2m",
                    "name": "Staging API Key",
                    "secret": "sk_test_51LqW6KBz9xYz987654321zyxwvutsrq",
                    "created": "2024-02-01T10:15:00Z",
                    "last_used": "2024-06-07T11:45:22Z",
                    "scopes": ["read", "write"],
                    "active": True
                },
                {
                    "id": "key_dev_3n4o5p6q7r8s",
                    "name": "Development API Key",
                    "secret": "sk_test_dev_51LqW6KBz9xYz111111111aaaaaa",
                    "created": "2024-03-10T16:20:00Z",
                    "last_used": "2024-06-08T08:10:00Z",
                    "scopes": ["read"],
                    "active": True
                }
            ],
            "database_credentials": {
                "host": "db-prod-01.internal.company.com",
                "port": 5432,
                "username": "dbadmin",
                "password": "Pr0d_DB_P@ss_2024",
                "database": "production_db"
            },
            "redis_url": "redis://:RedisPass123@redis-cache-01.internal:6379/0",
            "jwt_secret": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9secret_key_production_2024"
        }
        
        response_json = json.dumps(response_data, indent=2)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Server', 'nginx/1.25.1')
        self.send_header('X-API-Version', 'v1')
        self.end_headers()
        self.wfile.write(response_json.encode('utf-8'))
    
    def _serve_404(self):
        """Serve 404 error with nginx-style error page"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
    <style>
        html { color-scheme: light dark; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto Mono", 
                         "Helvetica Neue", sans-serif;
            margin: 0;
            padding: 0;
        }
        h1 { display: block; margin: 0 0 8px 0; font-size: 72px; font-weight: bold; color: #f8f9fa; }
        span { display: block; color: #bcc3cd; }
    </style>
</head>
<body bgcolor="#ffffff">
    <center><h1>404</h1></center>
    <center><span>Not Found</span></center>
    <hr><center>nginx/1.25.1 (Ubuntu)</center>
</body>
</html>"""
        
        self.send_response(404)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Server', 'nginx/1.25.1')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))


class HTTPCanary(BaseCanary):
    """
    HTTP Honeypot Service
    
    Presents a fake web server with realistic endpoints that capture
    and log web-based reconnaissance and attack attempts.
    """
    
    def __init__(
        self,
        port: int,
        name: str,
        fake_data: dict,
        alert_callback: Callable[[Dict[str, Any]], None]
    ):
        """
        Initialize HTTP Canary
        
        Args:
            port: Port to listen on
            name: Canary name
            fake_data: Fake data dictionary
            alert_callback: Alert callback function
        """
        super().__init__(port, name, fake_data, alert_callback)
        self.http_server = None
        self.server_thread = None
        
        # Set class variable for handler access
        HTTPRequestHandler.canary_instance = self
    
    def start(self):
        """Start the HTTP honeypot server"""
        try:
            # Create HTTP server
            self.http_server = HTTPServer(('0.0.0.0', self.port), HTTPRequestHandler)
            
            # Set timeout for server.handle_request()
            self.http_server.timeout = 1
            
            self.running = True
            
            # Start server thread
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self.server_thread.start()
            
            logger.info(
                f"[{self.name}] HTTP Honeypot started on 0.0.0.0:{self.port} "
                f"with endpoints: /admin, /api/v1/status, /api/v1/keys"
            )
        
        except Exception as e:
            logger.error(f"[{self.name}] Failed to start HTTP server: {e}", exc_info=True)
            self.running = False
    
    def _run_server(self):
        """Run the HTTP server (called in background thread)"""
        try:
            while self.running:
                self.http_server.handle_request()
        except Exception as e:
            if self.running:
                logger.error(f"[{self.name}] HTTP server error: {e}", exc_info=True)
    
    def stop(self):
        """Stop the HTTP honeypot server"""
        try:
            self.running = False
            
            if self.http_server:
                self.http_server.server_close()
            
            logger.info(f"[{self.name}] HTTP Honeypot stopped")
        
        except Exception as e:
            logger.error(f"[{self.name}] Error stopping HTTP server: {e}", exc_info=True)
