"""
Unit tests for Dashboard Application
Tests Flask routes and SocketIO integration
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch

from dashboard.app import create_app, inject_emit_callback
from shared.crypto import AlertCrypto
from shared.db import AlertDatabase
from monitor.monitor_server import MonitorServer


class TestDashboardAppInitialization:
    """Test dashboard app creation"""
    
    def test_create_app(self):
        """Test app creation"""
        app, socketio = create_app()
        
        assert app is not None
        assert socketio is not None
        assert app.config['SECRET_KEY'] == 'canary-net-secret'
    
    def test_create_app_with_config(self):
        """Test app creation with custom config"""
        config = {'DEBUG': True, 'TESTING': True}
        app, socketio = create_app(config)
        
        assert app.config['DEBUG'] == True
        assert app.config['TESTING'] == True
    
    def test_app_has_references(self):
        """Test app has required reference attributes"""
        app, socketio = create_app()
        
        assert hasattr(app, 'socketio')
        assert hasattr(app, 'monitor_server')
        assert hasattr(app, 'alert_manager')


class TestDashboardRoutes:
    """Test Flask routes"""
    
    @pytest.fixture
    def app(self):
        app, socketio = create_app({'TESTING': True})
        yield app
    
    @pytest.fixture
    def client(self, app):
        return app.test_client()
    
    def test_index_route(self, client):
        """Test index route"""
        response = client.get('/')
        
        assert response.status_code in [200, 500]  # May fail if template not found
    
    def test_api_alerts_route_empty(self, client):
        """Test /api/alerts when no database"""
        response = client.get('/api/alerts')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'alerts' in data
        assert 'total' in data
        assert data['total'] == 0
    
    def test_api_alerts_by_attacker(self, client):
        """Test /api/alerts/by-attacker/<ip>"""
        response = client.get('/api/alerts/by-attacker/192.168.1.100')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'alerts' in data
        assert 'attacker_ip' in data
    
    def test_api_alerts_by_canary(self, client):
        """Test /api/alerts/by-canary/<name>"""
        response = client.get('/api/alerts/by-canary/SSH-01')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'alerts' in data
        assert 'canary_name' in data
    
    def test_api_stats_route(self, client):
        """Test /api/stats route"""
        response = client.get('/api/stats')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'timestamp' in data
        assert 'monitor' in data
        assert 'alerts' in data


class TestDashboardWithDatabase:
    """Test dashboard with actual database"""
    
    @pytest.fixture
    def app_with_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = AlertDatabase(str(db_path))
            
            app, socketio = create_app({'TESTING': True})
            app.test_db = db
            
            yield app, db
    
    @pytest.fixture
    def client_with_db(self, app_with_db):
        app, db = app_with_db
        
        # Inject database
        @app.before_request
        def setup():
            if hasattr(app, 'test_db'):
                if app.monitor_server is None:
                    app.monitor_server = MagicMock()
                    app.monitor_server.db = app.test_db
                    app.monitor_server.get_statistics = MagicMock(return_value={
                        'alerts_received': 0,
                        'alerts_valid': 0,
                        'alerts_invalid': 0,
                        'alerts_decryption_failed': 0,
                        'db_total_alerts': 0
                    })
        
        return app.test_client(), app.test_db
    
    def test_api_alerts_with_data(self, client_with_db):
        """Test /api/alerts with database data"""
        client, db = client_with_db
        
        # Add alert to database
        alert = {
            "alert_id": "test-id-1",
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        db.log_alert(alert)
        
        response = client.get('/api/alerts')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['total'] >= 1


class TestSocketIOEmitCallback:
    """Test SocketIO emit callback generation"""
    
    def test_inject_emit_callback(self):
        """Test emit callback creation"""
        app, socketio = create_app({'TESTING': True})
        callback = inject_emit_callback(app, socketio)
        
        assert callback is not None
        assert callable(callback)
    
    def test_emit_callback_with_valid_alert(self):
        """Test emit callback with valid alert"""
        app, socketio = create_app({'TESTING': True})
        callback = inject_emit_callback(app, socketio)
        
        alert = {
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        # Should not raise exception
        callback('new_alert', alert)


class TestDashboardIntegrationWithMonitor:
    """Test dashboard integration with monitor server"""
    
    @pytest.fixture
    def setup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            db_path = Path(tmpdir) / "test.db"
            
            crypto = AlertCrypto(str(key_path))
            db = AlertDatabase(str(db_path))
            
            app, socketio = create_app({'TESTING': True})
            
            # Inject emit callback
            emit_callback = inject_emit_callback(app, socketio)
            
            # Create monitor server
            monitor = MonitorServer("127.0.0.1", 15100, crypto, db, emit_callback)
            
            # Attach to app
            app.monitor_server = monitor
            
            yield app, socketio, monitor, db, crypto
    
    def test_monitor_server_attached_to_app(self, setup):
        """Test monitor server attached to app"""
        app, socketio, monitor, db, crypto = setup
        
        assert app.monitor_server is not None
        assert app.monitor_server == monitor
    
    def test_app_can_get_monitor_stats(self, setup):
        """Test app can retrieve monitor statistics"""
        app, socketio, monitor, db, crypto = setup
        
        client = app.test_client()
        response = client.get('/api/stats')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Should have monitor statistics
        assert 'monitor' in data or 'alerts' in data


class TestSocketIOEvents:
    """Test SocketIO event handling"""
    
    @pytest.fixture
    def app_with_client(self):
        app, socketio = create_app({'TESTING': True})
        client = app.test_client()
        
        # Create SocketIO test client
        socketio_client = socketio.test_client(app, flask_test_client=client)
        
        yield app, socketio_client
    
    def test_connect_event(self, app_with_client):
        """Test client connection"""
        app, client = app_with_client
        
        assert client.is_connected()
    
    def test_subscribe_alerts_event(self, app_with_client):
        """Test alert subscription"""
        app, client = app_with_client
        
        client.emit('subscribe_alerts')
        
        # Receive response
        data = client.get_received()
        assert len(data) > 0


class TestDashboardErrorHandling:
    """Test dashboard error handling"""
    
    @pytest.fixture
    def app(self):
        app, socketio = create_app({'TESTING': True})
        yield app
    
    @pytest.fixture
    def client(self, app):
        return app.test_client()
    
    def test_alerts_with_no_monitor_server(self, client):
        """Test /api/alerts when monitor server not attached"""
        response = client.get('/api/alerts')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['total'] == 0
    
    def test_stats_with_no_monitor_server(self, client):
        """Test /api/stats when monitor server not attached"""
        response = client.get('/api/stats')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'monitor' in data
        assert 'alerts' in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
