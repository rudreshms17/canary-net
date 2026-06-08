"""
Fake Data Generator for Honeypot Canaries
Generates realistic but identifiable fake data for each canary instance
"""

import uuid
import random
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any


class FakeDataGenerator:
    """
    Generate realistic fake data for honeypot canaries
    Each instance generates UNIQUE data with embedded canary identifiers
    """
    
    def __init__(self, canary_name: str):
        """
        Initialize generator with canary name
        
        Args:
            canary_name: Name of the canary (e.g., "PROD-SSH-01")
        """
        self.canary_name = canary_name
        self.instance_id = str(uuid.uuid4())[:8]  # Short unique ID
        self.seed = hash(canary_name + self.instance_id) % 10000
        random.seed(self.seed)
    
    # ========================
    # FTP File Generation
    # ========================
    
    def generate_ftp_files(self) -> List[str]:
        """
        Generate list of realistic corporate filenames with embedded canary ID
        
        Returns:
            List of fake corporate filenames
        """
        current_year = datetime.now().year
        prev_year = current_year - 1
        
        # Base filenames with placeholders for timestamps
        base_files = [
            "Q3_{year}_financials_DRAFT.xlsx",
            "Q4_{year}_revenue_projections.xlsx",
            "{prev_year}_employee_records.csv",
            "VPN_credentials_backup.txt",
            "server_passwords_archive.csv",
            "AWS_access_keys_{canary_short}.txt",
            "database_backups_index.json",
            "customer_database_2024.db",
            "internal_api_documentation.pdf",
            "salary_schedule_{year}.xlsx",
            "SSH_keys_production.tar.gz",
            "backup_vault_keys.pem",
            "SSL_certificates_archive.zip",
            "network_topology_diagram.pdf",
            "incident_response_playbook.docx",
            "penetration_test_results_{year}.xlsx",
            "security_audit_findings.pdf",
            "admin_credentials_list_{canary_short}.txt",
            "domain_admin_passwords.csv",
            "source_code_repository_backup.tar.gz",
        ]
        
        canary_short = self.canary_name.split('-')[1][:3]  # e.g., "SSH" from "PROD-SSH-01"
        
        files = []
        for filename in base_files:
            # Substitute canary identifier and years
            filename = filename.format(
                year=current_year,
                prev_year=prev_year,
                canary_short=canary_short,
                instance_id=self.instance_id
            )
            files.append(filename)
        
        # Add instance-specific identifiable files
        files.extend([
            f"honeypot_{self.canary_name}_{self.instance_id}.log",
            f"tracking_{self.instance_id}.json",
        ])
        
        return files
    
    # ========================
    # SSH Banner Generation
    # ========================
    
    def generate_ssh_banner(self) -> str:
        """
        Generate realistic SSH banner for a server
        Includes embedded canary identifier for tracking
        
        Returns:
            SSH protocol banner string
        """
        # Parse canary name to generate server info
        parts = self.canary_name.split('-')  # e.g., ["PROD", "SSH", "01"]
        env = parts[0] if len(parts) > 0 else "PROD"  # PROD, DEV, TEST
        node_id = parts[2] if len(parts) > 2 else "01"
        
        # Generate server hostname from canary
        server_names = [
            f"server-{env.lower()}-{node_id}",
            f"auth-{env.lower()}-{node_id}",
            f"jump-{env.lower()}-{node_id}",
            f"bastion-{env.lower()}-{node_id}",
        ]
        hostname = random.choice(server_names)
        
        # SSH server versions
        ssh_versions = [
            "OpenSSH_7.4",
            "OpenSSH_8.0",
            "OpenSSH_8.2p1",
            "OpenSSH_8.6p1",
            "OpenSSH_9.0",
            "OpenSSH_9.3p1",
        ]
        version = random.choice(ssh_versions)
        
        # OS fingerprints
        os_types = [
            "Ubuntu_20.04-LTS",
            "CentOS_7.9",
            "RHEL_8.5",
            "Ubuntu_22.04-LTS",
            "Debian_11",
        ]
        os_type = random.choice(os_types)
        
        # Build banner with embedded instance ID for tracking
        banner = f"SSH-2.0-{version} {hostname} [{self.instance_id}]"
        
        return banner
    
    # ========================
    # HTTP Admin Page Generation
    # ========================
    
    def generate_http_admin_page(self, server_name: str = None) -> str:
        """
        Generate fake admin login HTML page with embedded tracking identifier
        
        Args:
            server_name: Optional server/service name (defaults to canary name)
        
        Returns:
            HTML string for admin login page
        """
        if not server_name:
            server_name = self.canary_name
        
        # Generate realistic internal server name
        internal_names = [
            f"admin-{self.instance_id}",
            f"manage-{self.instance_id}",
            f"dashboard-{self.instance_id}",
            f"portal-{self.instance_id}",
        ]
        internal_server = random.choice(internal_names)
        
        # Generate build/version info
        build_num = random.randint(1000, 9999)
        build_date = (datetime.now() - timedelta(days=random.randint(1, 180))).strftime("%Y-%m-%d")
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal - {server_name}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }}
        .login-container {{
            background: white;
            padding: 50px 40px;
            border-radius: 8px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.3);
            width: 100%;
            max-width: 450px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
        }}
        .logo {{
            font-size: 28px;
            font-weight: 700;
            color: #1e3c72;
            margin-bottom: 10px;
        }}
        .server-info {{
            font-size: 12px;
            color: #666;
            font-family: monospace;
            background: #f5f5f5;
            padding: 8px 12px;
            border-radius: 4px;
            margin-top: 10px;
            word-break: break-all;
        }}
        h1 {{
            text-align: center;
            color: #333;
            margin-bottom: 30px;
            font-size: 22px;
        }}
        .form-group {{
            margin-bottom: 25px;
        }}
        label {{
            display: block;
            margin-bottom: 10px;
            color: #555;
            font-weight: 600;
            font-size: 14px;
        }}
        input[type="text"],
        input[type="password"],
        select {{
            width: 100%;
            padding: 14px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            transition: border-color 0.3s;
            font-family: inherit;
        }}
        input[type="text"]:focus,
        input[type="password"]:focus,
        select:focus {{
            outline: none;
            border-color: #1e3c72;
            box-shadow: 0 0 0 3px rgba(30, 60, 114, 0.1);
        }}
        .checkbox-group {{
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }}
        input[type="checkbox"] {{
            margin-right: 8px;
            cursor: pointer;
        }}
        .checkbox-group label {{
            margin: 0;
            font-weight: 500;
            cursor: pointer;
        }}
        button {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(30, 60, 114, 0.4);
        }}
        button:active {{
            transform: translateY(0);
        }}
        .error-message {{
            color: #dc3545;
            font-size: 13px;
            margin-top: 10px;
            display: none;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #999;
        }}
        .footer a {{
            color: #1e3c72;
            text-decoration: none;
        }}
        .footer a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <div class="header">
            <div class="logo">{server_name}</div>
            <div class="server-info">
                Internal Server: {internal_server}<br>
                Build: {build_num} ({build_date})<br>
                Tracking ID: {self.instance_id}
            </div>
        </div>
        
        <h1>Administrator Portal</h1>
        
        <form method="POST" action="/admin">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username" placeholder="admin">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password" placeholder="••••••••">
            </div>
            
            <div class="form-group">
                <label for="totp">Two-Factor Code (optional)</label>
                <input type="text" id="totp" name="totp" placeholder="000000" maxlength="6">
            </div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="remember" name="remember" value="true">
                <label for="remember">Remember this device for 30 days</label>
            </div>
            
            <button type="submit">Sign In</button>
            <div class="error-message" id="error">Invalid credentials. Please try again.</div>
        </form>
        
        <div class="footer">
            <p>Secure login portal for authorized administrators only.</p>
            <p><a href="#">Forgot Password?</a> | <a href="#">Support</a></p>
            <p style="margin-top: 15px; font-size: 11px; color: #bbb;">
                System Version: {self.canary_name} v{build_num}<br>
                © 2024 Internal Systems. All rights reserved.
            </p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    # ========================
    # API Key Generation
    # ========================
    
    def generate_api_keys(self) -> Dict[str, Any]:
        """
        Generate realistic-looking fake API keys and tokens
        Each key includes embedded canary identifier for tracking
        
        Returns:
            Dictionary with fake credentials
        """
        # Generate realistic-looking API keys with structure: prefix_randomBase64
        def generate_key(prefix: str, length: int = 32) -> str:
            """Generate a realistic API key with given prefix"""
            import string
            chars = string.ascii_letters + string.digits
            suffix = ''.join(random.choices(chars, k=length))
            return f"{prefix}_{suffix}"
        
        # Generate token with timestamp and instance ID
        def generate_token(service: str) -> str:
            """Generate realistic JWT-like token"""
            import base64
            timestamp = int(datetime.now().timestamp())
            header = base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip('=')
            payload = base64.b64encode(
                json.dumps({
                    "service": service,
                    "canary": self.instance_id,
                    "iat": timestamp,
                    "exp": timestamp + 86400
                }).encode()
            ).decode().rstrip('=')
            signature = self.instance_id.ljust(43, '0')[:43]
            return f"{header}.{payload}.{signature}"
        
        api_keys = {
            "aws": {
                "access_key_id": f"AKIA{random.randint(10**15, 10**16)}{self.instance_id[:4]}",
                "secret_access_key": generate_key("aws_secret", 40),
                "region": random.choice(["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]),
            },
            "stripe": {
                "publishable_key": generate_key("pk_live", 32),
                "secret_key": generate_key("sk_live", 32),
                "api_version": "2023-10-16",
            },
            "github": {
                "token": f"ghp_{generate_key('', 36)}",
                "oauth_app_id": f"{random.randint(100000, 999999)}",
                "oauth_app_secret": generate_key("", 40),
            },
            "slack": {
                "bot_token": f"xoxb-{random.randint(10**15, 10**16)}-{random.randint(10**15, 10**16)}-{generate_key('', 24)}",
                "webhook_url": f"https://hooks.slack.com/services/{uuid.uuid4().hex[:12]}/{uuid.uuid4().hex[:12]}/{self.instance_id}",
            },
            "database": {
                "connection_string": f"postgresql://admin:{self.instance_id}@db-prod-{self.instance_id}.internal:5432/production?sslmode=require",
                "user": "admin",
                "password": generate_key("dbpass", 24),
                "host": f"db-prod-{self.instance_id}.internal",
                "port": 5432,
                "database": "production",
            },
            "google": {
                "service_account_email": f"service-account-{self.instance_id}@project-{random.randint(100000, 999999)}.iam.gserviceaccount.com",
                "private_key_id": uuid.uuid4().hex,
                "private_key": f"-----BEGIN PRIVATE KEY-----\n{generate_key('', 64)}\n-----END PRIVATE KEY-----",
                "client_id": f"{random.randint(10**18, 10**19)}",
            },
            "jwt": {
                "access_token": generate_token("admin_portal"),
                "refresh_token": generate_token("refresh"),
                "token_type": "Bearer",
                "expires_in": 3600,
            },
            "internal_service": {
                "api_key": generate_key("service_key", 32),
                "client_id": self.instance_id,
                "client_secret": generate_key("client_secret", 40),
                "endpoint": f"https://api.internal.{self.canary_name.lower().replace('-', '.')}/v1",
            },
            "metadata": {
                "canary_name": self.canary_name,
                "instance_id": self.instance_id,
                "generated_at": datetime.now().isoformat(),
                "tracking_id": uuid.uuid4().hex,
            }
        }
        
        return api_keys
    
    # ========================
    # SSH Credentials Generation
    # ========================
    
    def generate_ssh_credentials(self) -> Dict[str, str]:
        """
        Generate fake SSH credentials with embedded canary identifier
        
        Returns:
            Dictionary with SSH credentials
        """
        admin_users = ["root", "admin", "sysadmin", "deploy", "app"]
        service_users = ["postgres", "mongodb", "elasticsearch", "redis"]
        app_users = ["webapp", "apiserver", "worker", "scheduler"]
        
        credentials = {}
        
        # Generate some valid-looking credentials
        for user_type, users in [("admin", admin_users), ("service", service_users), ("app", app_users)]:
            for user in users[:2]:  # 2 users per type
                password = f"{self.instance_id}_" + ''.join(
                    random.choices('ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789', k=16)
                )
                credentials[f"{user_type}_{user}"] = {
                    "username": user,
                    "password": password,
                    "key_fingerprint": f"SHA256:{self.instance_id.ljust(43, 'a')[:43]}",
                }
        
        return credentials


# ========================
# Helper Functions
# ========================

def generate_fake_data_for_canary(canary_name: str) -> Dict[str, Any]:
    """
    Convenience function to generate all fake data for a canary
    
    Args:
        canary_name: Name of the canary
    
    Returns:
        Dictionary with all generated fake data
    """
    generator = FakeDataGenerator(canary_name)
    
    return {
        "canary_name": canary_name,
        "instance_id": generator.instance_id,
        "ftp_files": generator.generate_ftp_files(),
        "ssh_banner": generator.generate_ssh_banner(),
        "http_admin_page": generator.generate_http_admin_page(),
        "api_keys": generator.generate_api_keys(),
        "ssh_credentials": generator.generate_ssh_credentials(),
    }
