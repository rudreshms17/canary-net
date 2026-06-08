"""
Configuration loader for Canary-Net
Loads config.yaml with validation and defaults
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class ConfigError(Exception):
    """Raised when configuration is invalid or missing"""
    pass


class Config:
    """Configuration management for Canary-Net"""

    # Default configuration
    DEFAULT_CONFIG = {
        'monitor': {
            'host': '0.0.0.0',
            'port': 9999
        },
        'broadcast_port': 9998,
        'dashboard_port': 5000,
        'key_path': './canary.key',
        'db_path': './alerts.db',
        'canaries': {
            'ftp': {
                'enabled': True,
                'port': 21,
                'name': 'PROD-FTP-01'
            },
            'ssh': {
                'enabled': True,
                'port': 22,
                'name': 'PROD-SSH-01'
            },
            'http': {
                'enabled': True,
                'port': 8080,
                'name': 'PROD-WEB-01'
            },
            'smb': {
                'enabled': True,
                'port': 4450,
                'name': 'PROD-FILE-01'
            }
        }
    }

    # Required fields for validation
    REQUIRED_FIELDS = [
        'monitor.host',
        'monitor.port',
        'broadcast_port',
        'dashboard_port',
        'key_path',
        'db_path',
        'canaries'
    ]

    def __init__(self, config_path: str = 'config.yaml'):
        """
        Initialize configuration from YAML file
        
        Args:
            config_path: Path to config.yaml file
            
        Raises:
            ConfigError: If required fields are missing
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self._validate_config()

    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from YAML file
        Generate default if file doesn't exist
        
        Returns:
            Configuration dictionary
        """
        if not self.config_path.exists():
            print(f"[Config] No config.yaml found at {self.config_path}")
            print(f"[Config] Generating default config...")
            self._generate_default_config()

        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                if not config:
                    raise ConfigError("config.yaml is empty")
                print(f"[Config] Loaded configuration from {self.config_path}")
                return config
        except yaml.YAMLError as e:
            raise ConfigError(f"Failed to parse config.yaml: {e}")
        except IOError as e:
            raise ConfigError(f"Failed to read config.yaml: {e}")

    def _generate_default_config(self) -> None:
        """
        Generate default config.yaml file
        
        Raises:
            ConfigError: If file cannot be written
        """
        try:
            # Ensure parent directory exists
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                yaml.dump(self.DEFAULT_CONFIG, f, default_flow_style=False, sort_keys=False)
            
            print(f"[Config] Generated default config at {self.config_path}")
        except IOError as e:
            raise ConfigError(f"Failed to generate default config: {e}")

    def _validate_config(self) -> None:
        """
        Validate that all required fields are present
        
        Raises:
            ConfigError: If required fields are missing
        """
        missing_fields = []

        for field_path in self.REQUIRED_FIELDS:
            if not self._get_nested_value(field_path):
                missing_fields.append(field_path)

        if missing_fields:
            raise ConfigError(
                f"Missing required configuration fields: {', '.join(missing_fields)}"
            )

        # Validate canary configuration
        canaries = self.get('canaries', {})
        if not isinstance(canaries, dict):
            raise ConfigError("'canaries' must be a dictionary")

        for service_name, config_dict in canaries.items():
            if not isinstance(config_dict, dict):
                raise ConfigError(f"Canary '{service_name}' configuration must be a dictionary")

            required_canary_fields = ['enabled', 'port', 'name']
            for field in required_canary_fields:
                if field not in config_dict:
                    raise ConfigError(
                        f"Canary '{service_name}' missing required field: {field}"
                    )

        print(f"[Config] Configuration validation passed")

    def _get_nested_value(self, path: str) -> Optional[Any]:
        """
        Get nested value from config using dot notation
        
        Args:
            path: Dot-separated path (e.g., 'monitor.host')
            
        Returns:
            Value or None if not found
        """
        keys = path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None

        return value

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value
        
        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        value = self._get_nested_value(key)
        return value if value is not None else default

    def get_monitor_config(self) -> Dict[str, Any]:
        """Get monitor server configuration"""
        return self.get('monitor', {})

    def get_monitor_host(self) -> str:
        """Get monitor server host"""
        return self.get('monitor.host', '0.0.0.0')

    def get_monitor_port(self) -> int:
        """Get monitor server port"""
        return self.get('monitor.port', 9999)

    def get_broadcast_port(self) -> int:
        """Get UDP broadcast port"""
        return self.get('broadcast_port', 9998)

    def get_dashboard_port(self) -> int:
        """Get dashboard Flask port"""
        return self.get('dashboard_port', 5000)

    def get_key_path(self) -> str:
        """Get encryption key file path"""
        return self.get('key_path', './canary.key')

    def get_db_path(self) -> str:
        """Get database file path"""
        return self.get('db_path', './alerts.db')

    def get_canaries(self) -> Dict[str, Dict[str, Any]]:
        """Get all canary configurations"""
        return self.get('canaries', {})

    def get_canary_config(self, service_name: str) -> Optional[Dict[str, Any]]:
        """
        Get configuration for specific canary
        
        Args:
            service_name: Canary service name (ftp, ssh, http, smb)
            
        Returns:
            Canary configuration or None
        """
        return self.get_canaries().get(service_name)

    def get_enabled_canaries(self) -> Dict[str, Dict[str, Any]]:
        """Get only enabled canary configurations"""
        return {
            name: config
            for name, config in self.get_canaries().items()
            if config.get('enabled', False)
        }

    def __repr__(self) -> str:
        """String representation of configuration"""
        return f"<Config path={self.config_path}>"
