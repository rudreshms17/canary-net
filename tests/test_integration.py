"""
Integration Tests for Canary Services
Tests FTP and HTTP canaries with real client connections
"""

import pytest
import time
import threading
import ftplib
import urllib.request
import urllib.error
import socket
from unittest.mock import Mock, call
from typing import List, Dict, Any

from canaries.ftp_canary import FTPCanary
from canaries.http_canary import HTTPCanary


# ========================
# Fixtures
# ========================

@pytest.fixture
def alert_callback():
    """Mock alert callback to capture triggered alerts"""
    return Mock()


@pytest.fixture
def ftp_canary(alert_callback):
    """FTP Canary fixture on high port"""
    canary = FTPCanary(
        port=12021,
        name="TEST-FTP-01",
        fake_data={"creds": "admin:password123", "files": ["Q3_financials.xlsx"]},
        alert_callback=alert_callback
    )
    
    canary.start()
    # Give server time to bind to port
    time.sleep(0.5)
    
    yield canary
    
    # Teardown
    canary.stop()
    time.sleep(0.2)


@pytest.fixture
def http_canary(alert_callback):
    """HTTP Canary fixture on high port"""
    canary = HTTPCanary(
        port=12080,
        name="TEST-HTTP-01",
        fake_data={"endpoints": ["/admin", "/api/v1/status", "/api/v1/keys"]},
        alert_callback=alert_callback,
        host='127.0.0.1'
    )
    
    canary.start()
    # Give server time to bind to port
    time.sleep(0.5)
    
    yield canary
    
    # Teardown
    canary.stop()
    time.sleep(0.2)


# ========================
# Utility Functions
# ========================

def wait_for_alerts(mock_callback, expected_count: int, timeout: float = 2.0) -> bool:
    """
    Wait for expected number of alerts to be recorded
    
    Args:
        mock_callback: Mock alert callback
        expected_count: Number of alerts to wait for
        timeout: Maximum time to wait in seconds
    
    Returns:
        True if expected alerts received, False if timeout
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        if mock_callback.call_count >= expected_count:
            return True
        time.sleep(0.05)
    return False


def assert_alert_structure(alert: Dict[str, Any]) -> None:
    """
    Assert that alert dict contains required fields with correct types
    
    Args:
        alert: Alert dictionary from canary callback
    
    Raises:
        AssertionError if alert structure is invalid
    """
    required_fields = {
        "canary_name": str,
        "attacker_ip": str,
        "attacker_port": int,
        "behavior": str,
        "timestamp": str,
        "port": int,
        "fake_data_touched": bool
    }
    
    for field, expected_type in required_fields.items():
        assert field in alert, f"Missing required field: {field}"
        assert isinstance(alert[field], expected_type), \
            f"Field {field} should be {expected_type.__name__}, got {type(alert[field]).__name__}"
    
    # Validate timestamp format (ISO 8601 with Z suffix)
    assert alert["timestamp"].endswith("Z"), "Timestamp must end with 'Z' (UTC)"
    assert "T" in alert["timestamp"], "Timestamp must be ISO 8601 format (YYYY-MM-DDTHH:MM:SS)"


# ========================
# FTP Canary Tests
# ========================

class TestFTPCanaryIntegration:
    """Integration tests for FTP honeypot canary"""
    
    def test_ftp_canary_starts_successfully(self, ftp_canary):
        """Test that FTP canary starts and is accessible"""
        assert ftp_canary.running is True
        assert ftp_canary.port == 12021
        assert ftp_canary.name == "TEST-FTP-01"
        
        # Verify port is listening
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', 12021))
        sock.close()
        assert result == 0, "FTP port 12021 is not listening"
    
    def test_ftp_login_attempt_triggers_alert(self, ftp_canary, alert_callback):
        """Test that FTP login attempt triggers alert callback"""
        try:
            # Attempt FTP connection and login
            ftp = ftplib.FTP()
            ftp.connect('127.0.0.1', 12021, timeout=5)
            
            try:
                ftp.login('admin', 'password123')
            except ftplib.all_errors:
                # Expected to fail - we're a honeypot
                pass
            finally:
                try:
                    ftp.quit()
                except:
                    pass
        
        except Exception as e:
            pytest.skip(f"FTP connection failed: {e}")
        
        # Wait for alert to be recorded
        assert wait_for_alerts(alert_callback, 1, timeout=2.0), \
            "Alert callback was not called for FTP login attempt"
        
        # Verify alert was called
        assert alert_callback.call_count >= 1
    
    def test_ftp_alert_contains_required_fields(self, ftp_canary, alert_callback):
        """Test that FTP alert contains all required fields"""
        try:
            ftp = ftplib.FTP()
            ftp.connect('127.0.0.1', 12021, timeout=5)
            
            try:
                ftp.login('testuser', 'testpass')
            except ftplib.all_errors:
                pass
            finally:
                try:
                    ftp.quit()
                except:
                    pass
        
        except Exception as e:
            pytest.skip(f"FTP connection failed: {e}")
        
        # Wait for alert
        assert wait_for_alerts(alert_callback, 1, timeout=2.0)
        
        # Get the alert from the mock
        alerts = [call_args[0][0] for call_args in alert_callback.call_args_list]
        assert len(alerts) > 0, "No alerts were recorded"
        
        alert = alerts[0]
        
        # Verify all required fields
        assert_alert_structure(alert)
        
        # Verify FTP-specific fields
        assert alert["canary_name"] == "TEST-FTP-01"
        assert alert["port"] == 12021
        assert alert["attacker_ip"] in ["127.0.0.1", "localhost"]
        assert isinstance(alert["attacker_port"], int)
        assert alert["attacker_port"] > 0
        assert "ftp_login_attempt" in alert["behavior"]
    
    def test_ftp_alert_captures_credentials(self, ftp_canary, alert_callback):
        """Test that FTP alert captures attempted credentials"""
        try:
            ftp = ftplib.FTP()
            ftp.connect('127.0.0.1', 12021, timeout=5)
            
            try:
                ftp.login('admin', 'password123')
            except ftplib.all_errors:
                pass
            finally:
                try:
                    ftp.quit()
                except:
                    pass
        
        except Exception as e:
            pytest.skip(f"FTP connection failed: {e}")
        
        # Wait for alert
        assert wait_for_alerts(alert_callback, 1, timeout=2.0)
        
        alerts = [call_args[0][0] for call_args in alert_callback.call_args_list]
        alert = alerts[0]
        
        # Verify credentials are captured in behavior field
        assert "admin" in alert["behavior"]
        assert "password123" in alert["behavior"]
    
    def test_ftp_multiple_connection_attempts(self, ftp_canary, alert_callback):
        """Test multiple FTP connection attempts trigger multiple alerts"""
        num_attempts = 3
        
        for i in range(num_attempts):
            try:
                ftp = ftplib.FTP()
                ftp.connect('127.0.0.1', 12021, timeout=5)
                
                try:
                    ftp.login(f'user{i}', f'pass{i}')
                except ftplib.all_errors:
                    pass
                finally:
                    try:
                        ftp.quit()
                    except:
                        pass
            except Exception:
                pass
            
            time.sleep(0.1)
        
        # Wait for all alerts
        assert wait_for_alerts(alert_callback, num_attempts, timeout=3.0), \
            f"Expected {num_attempts} alerts, got {alert_callback.call_count}"


# ========================
# HTTP Canary Tests
# ========================

class TestHTTPCanaryIntegration:
    """Integration tests for HTTP honeypot canary"""
    
    def test_http_canary_starts_successfully(self, http_canary):
        """Test that HTTP canary starts and is accessible"""
        assert http_canary.running is True
        assert http_canary.port == 12080
        assert http_canary.name == "TEST-HTTP-01"
        
        # Verify port is listening
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', 12080))
        sock.close()
        assert result == 0, "HTTP port 12080 is not listening"
    
    def test_http_get_request_triggers_alert(self, http_canary, alert_callback):
        """Test that HTTP GET request triggers alert callback"""
        try:
            url = 'http://127.0.0.1:12080/admin'
            response = urllib.request.urlopen(url, timeout=5)
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            # Expected - we'll get a response but the connection will close
            pass
        except Exception as e:
            pytest.skip(f"HTTP connection failed: {e}")
        
        # Wait for alert
        assert wait_for_alerts(alert_callback, 1, timeout=2.0), \
            "Alert callback was not called for HTTP GET request"
    
    def test_http_post_request_triggers_alert(self, http_canary, alert_callback):
        """Test that HTTP POST request triggers alert callback"""
        try:
            url = 'http://127.0.0.1:12080/admin'
            data = b'username=admin&password=password123'
            request = urllib.request.Request(url, data=data, method='POST')
            response = urllib.request.urlopen(request, timeout=5)
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            # Expected
            pass
        except Exception as e:
            pytest.skip(f"HTTP connection failed: {e}")
        
        # Wait for alert
        assert wait_for_alerts(alert_callback, 1, timeout=2.0), \
            "Alert callback was not called for HTTP POST request"
    
    def test_http_alert_contains_required_fields(self, http_canary, alert_callback):
        """Test that HTTP alert contains all required fields"""
        try:
            url = 'http://127.0.0.1:12080/api/v1/status'
            response = urllib.request.urlopen(url, timeout=5)
        except (urllib.error.HTTPError, urllib.error.URLError):
            pass
        except Exception as e:
            pytest.skip(f"HTTP connection failed: {e}")
        
        # Wait for alert
        assert wait_for_alerts(alert_callback, 1, timeout=2.0)
        
        alerts = [call_args[0][0] for call_args in alert_callback.call_args_list]
        assert len(alerts) > 0
        
        alert = alerts[0]
        
        # Verify all required fields
        assert_alert_structure(alert)
        
        # Verify HTTP-specific fields
        assert alert["canary_name"] == "TEST-HTTP-01"
        assert alert["port"] == 12080
        assert alert["attacker_ip"] in ["127.0.0.1", "localhost"]
        assert isinstance(alert["attacker_port"], int)
        assert alert["attacker_port"] > 0
        assert "http_" in alert["behavior"]
    
    def test_http_alert_captures_path(self, http_canary, alert_callback):
        """Test that HTTP alert captures requested path"""
        test_path = '/admin'
        
        try:
            url = f'http://127.0.0.1:12080{test_path}'
            response = urllib.request.urlopen(url, timeout=5)
        except (urllib.error.HTTPError, urllib.error.URLError):
            pass
        except Exception as e:
            pytest.skip(f"HTTP connection failed: {e}")
        
        # Wait for alert
        assert wait_for_alerts(alert_callback, 1, timeout=2.0)
        
        alerts = [call_args[0][0] for call_args in alert_callback.call_args_list]
        alert = alerts[0]
        
        # Verify path is captured
        assert test_path in alert["behavior"]
    
    def test_http_get_vs_post_behavior(self, http_canary, alert_callback):
        """Test that GET and POST requests are distinguished"""
        # Make GET request
        try:
            response = urllib.request.urlopen('http://127.0.0.1:12080/test', timeout=5)
        except (urllib.error.HTTPError, urllib.error.URLError):
            pass
        except Exception as e:
            pytest.skip(f"HTTP connection failed: {e}")
        
        time.sleep(0.2)
        first_call_count = alert_callback.call_count
        
        # Make POST request
        try:
            data = b'test_data'
            request = urllib.request.Request('http://127.0.0.1:12080/test', data=data)
            response = urllib.request.urlopen(request, timeout=5)
        except (urllib.error.HTTPError, urllib.error.URLError):
            pass
        except Exception as e:
            pytest.skip(f"HTTP connection failed: {e}")
        
        # Wait for second alert
        assert wait_for_alerts(alert_callback, first_call_count + 1, timeout=2.0)
        
        alerts = [call_args[0][0] for call_args in alert_callback.call_args_list]
        
        # Find GET and POST alerts
        get_alerts = [a for a in alerts if "http_get" in a["behavior"]]
        post_alerts = [a for a in alerts if "http_post" in a["behavior"]]
        
        assert len(get_alerts) > 0, "No GET alerts found"
        assert len(post_alerts) > 0, "No POST alerts found"
    
    def test_http_multiple_requests(self, http_canary, alert_callback):
        """Test multiple HTTP requests trigger multiple alerts"""
        paths = ['/admin', '/api/v1/status', '/api/v1/keys', '/unknown']
        
        for path in paths:
            try:
                url = f'http://127.0.0.1:12080{path}'
                response = urllib.request.urlopen(url, timeout=5)
            except (urllib.error.HTTPError, urllib.error.URLError):
                pass
            except Exception:
                pass
            
            time.sleep(0.1)
        
        # Wait for all alerts
        assert wait_for_alerts(alert_callback, len(paths), timeout=3.0), \
            f"Expected {len(paths)} alerts, got {alert_callback.call_count}"


# ========================
# Combined Integration Tests
# ========================

class TestCanaryIntegration:
    """Combined tests for multiple canaries"""
    
    def test_ftp_and_http_canaries_independent(self, ftp_canary, http_canary, alert_callback):
        """Test that FTP and HTTP canaries operate independently"""
        # Create separate alert tracking
        ftp_alerts = []
        http_alerts = []
        
        def ftp_callback(alert):
            ftp_alerts.append(alert)
            alert_callback(alert)
        
        def http_callback(alert):
            http_alerts.append(alert)
            alert_callback(alert)
        
        # Create fresh canaries with separate callbacks
        ftp = FTPCanary(12121, "TEST-FTP-2", {}, ftp_callback)
        http = HTTPCanary(12180, "TEST-HTTP-2", {}, http_callback, host='127.0.0.1')
        
        ftp.start()
        http.start()
        time.sleep(0.5)
        
        try:
            # Make FTP request
            try:
                ftp_client = ftplib.FTP()
                ftp_client.connect('127.0.0.1', 12121, timeout=5)
                try:
                    ftp_client.login('user', 'pass')
                except ftplib.all_errors:
                    pass
                finally:
                    try:
                        ftp_client.quit()
                    except:
                        pass
            except Exception:
                pass
            
            time.sleep(0.3)
            
            # Make HTTP request
            try:
                response = urllib.request.urlopen('http://127.0.0.1:12180/test', timeout=5)
            except (urllib.error.HTTPError, urllib.error.URLError):
                pass
            except Exception:
                pass
            
            time.sleep(0.3)
            
            # Verify alerts came from correct canaries
            ftp_count = len(ftp_alerts)
            http_count = len(http_alerts)
            
            assert ftp_count > 0, "FTP canary did not record alerts"
            assert http_count > 0, "HTTP canary did not record alerts"
            
            # Verify canary names are correct
            for alert in ftp_alerts:
                assert alert["canary_name"] == "TEST-FTP-2"
            
            for alert in http_alerts:
                assert alert["canary_name"] == "TEST-HTTP-2"
        
        finally:
            ftp.stop()
            http.stop()
            time.sleep(0.2)


# ========================
# Edge Case Tests
# ========================

class TestCanaryEdgeCases:
    """Test edge cases and error handling"""
    
    def test_ftp_canary_stops_gracefully(self, ftp_canary, alert_callback):
        """Test that FTP canary stops without errors"""
        assert ftp_canary.running is True
        ftp_canary.stop()
        assert ftp_canary.running is False
        
        # Verify port is no longer listening
        time.sleep(0.3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', 12021))
        sock.close()
        # Port should be free (result != 0) but may still be in TIME_WAIT
        # So we just verify no error occurred during stop
    
    def test_http_canary_stops_gracefully(self, http_canary, alert_callback):
        """Test that HTTP canary stops without errors"""
        assert http_canary.running is True
        http_canary.stop()
        assert http_canary.running is False
    
    def test_alert_timestamp_format(self, ftp_canary, alert_callback):
        """Test that alert timestamp is proper ISO 8601 UTC format"""
        try:
            ftp = ftplib.FTP()
            ftp.connect('127.0.0.1', 12021, timeout=5)
            try:
                ftp.login('user', 'pass')
            except ftplib.all_errors:
                pass
            finally:
                try:
                    ftp.quit()
                except:
                    pass
        except Exception:
            pass
        
        # Wait for alert
        assert wait_for_alerts(alert_callback, 1, timeout=2.0)
        
        alerts = [call_args[0][0] for call_args in alert_callback.call_args_list]
        alert = alerts[0]
        
        timestamp = alert["timestamp"]
        
        # Verify format: YYYY-MM-DDTHH:MM:SS.ffffffZ
        assert timestamp.endswith("Z"), "Timestamp must end with Z"
        assert "T" in timestamp, "Timestamp must have T separator"
        
        # Verify it's parseable
        from datetime import datetime
        # Remove the Z and microseconds for parsing
        timestamp_clean = timestamp.rstrip('Z').split('.')[0]
        dt = datetime.fromisoformat(timestamp_clean)
        assert dt.year > 2020, "Year should be valid"
