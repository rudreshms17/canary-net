"""
Flask Dashboard Application
Real-time alert monitoring interface with SocketIO
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def create_app(config=None):
    """
    Create and configure Flask app
    
    Args:
        config: Optional configuration object or dictionary.
                If passed, should NOT be a Config object (those are accessed via methods).
    
    Returns:
        Tuple of (app, socketio)
    """
    app = Flask(
        __name__,
        template_folder='templates',
        static_folder='static'
    )
    
    # Configuration
    app.config['SECRET_KEY'] = 'canary-net-secret'
    app.config['JSON_SORT_KEYS'] = False
    
    # Only update app config if config is a dictionary (not a Config object)
    if config and isinstance(config, dict):
        app.config.update(config)
    
    # Initialize SocketIO
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        logger=False,
        engineio_logger=False,
        async_mode='threading'
    )
    
    # Store references for background services
    app.socketio = socketio
    app.monitor_server = None
    app.alert_manager = None
    
    # =====================================
    # Routes
    # =====================================
    
    @app.route('/')
    def index():
        """Serve dashboard homepage"""
        try:
            return render_template('index.html')
        except Exception as e:
            logger.warning(f"[Dashboard] Template rendering failed: {e}")
            # Fallback HTML if template not found
            return """
<!DOCTYPE html>
<html>
<head>
    <title>Canary-Net Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #dc3545; }
        p { color: #666; }
        .status { background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 Canary-Net Distributed Honeypot</h1>
        <p>Real-time alert monitoring dashboard</p>
        <div class="status">
            <strong>Status:</strong> Dashboard Running<br>
            <strong>Timestamp:</strong> """ + datetime.utcnow().isoformat() + """
        </div>
        <hr>
        <h3>Available Endpoints:</h3>
        <ul>
            <li>GET /api/alerts - Get recent alerts</li>
            <li>GET /api/stats - Get aggregated statistics</li>
            <li>GET /health - Health check</li>
        </ul>
    </div>
</body>
</html>
            """
    
    @app.route('/health')
    def health():
        """Health check endpoint"""
        return jsonify({"status": "ok"})
    
    @app.route('/api/alerts')
    def get_alerts():
        """Get recent alerts as JSON"""
        try:
            limit = int(request.args.get('limit', 100))
            hours = int(request.args.get('hours', 24))
            
            if app.monitor_server and app.monitor_server.db:
                alerts = app.monitor_server.db.get_recent_alerts(hours=hours, limit=limit)
                return jsonify({
                    "alerts": alerts,
                    "total": len(alerts),
                    "timestamp": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"[Dashboard] Error fetching alerts: {e}")
        
        return jsonify({"alerts": [], "total": 0, "error": "Database not available"}), 503
    
    @app.route('/api/alerts/<alert_id>')
    def get_alert_detail(alert_id):
        """Get single alert detail by ID"""
        try:
            if app.monitor_server and app.monitor_server.db:
                session = app.monitor_server.db._get_session()
                from shared.db import Alert
                
                alert = session.query(Alert).filter(Alert.alert_id == alert_id).first()
                session.close()
                
                if not alert:
                    return jsonify({
                        "error": "Alert not found",
                        "alert_id": alert_id
                    }), 404
                
                return jsonify(alert.to_dict())
        
        except Exception as e:
            logger.error(f"[Dashboard] Error fetching alert detail: {e}")
        
        return jsonify({"error": "Database error"}), 500
    
    @app.route('/api/alerts/by-attacker/<attacker_ip>')
    def get_alerts_by_attacker(attacker_ip):
        """Get alerts from specific attacker"""
        try:
            limit = int(request.args.get('limit', 50))
            
            if app.monitor_server and app.monitor_server.db:
                alerts = app.monitor_server.db.get_alerts_by_ip(attacker_ip, limit=limit)
                return jsonify({
                    "attacker_ip": attacker_ip,
                    "alerts": alerts,
                    "total": len(alerts)
                })
        except Exception as e:
            logger.error(f"[Dashboard] Error fetching attacker alerts: {e}")
        
        return jsonify({"alerts": [], "total": 0, "error": "Database not available"}), 503
    
    @app.route('/api/alerts/by-canary/<canary_name>')
    def get_alerts_by_canary(canary_name):
        """Get alerts from specific canary"""
        try:
            limit = int(request.args.get('limit', 50))
            
            if app.monitor_server and app.monitor_server.db:
                alerts = app.monitor_server.db.get_alerts_by_canary(canary_name, limit=limit)
                return jsonify({
                    "canary_name": canary_name,
                    "alerts": alerts,
                    "total": len(alerts)
                })
        except Exception as e:
            logger.error(f"[Dashboard] Error fetching canary alerts: {e}")
        
        return jsonify({"alerts": [], "total": 0, "error": "Database not available"}), 503
    
    @app.route('/api/acknowledge/<alert_id>', methods=['POST'])
    def acknowledge_alert(alert_id):
        """Mark alert as acknowledged"""
        try:
            if app.monitor_server and app.monitor_server.db:
                result = app.monitor_server.db.acknowledge(alert_id)
                
                if result:
                    return jsonify({
                        "status": "acknowledged",
                        "alert_id": alert_id,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                else:
                    return jsonify({
                        "error": "Alert not found",
                        "alert_id": alert_id
                    }), 404
        
        except Exception as e:
            logger.error(f"[Dashboard] Error acknowledging alert: {e}")
        
        return jsonify({"error": "Database error"}), 500
    
    @app.route('/api/stats')
    def get_stats():
        """Get aggregated alert statistics"""
        try:
            stats = {
                "timestamp": datetime.utcnow().isoformat(),
                "db": {},
                "monitor": {},
                "alerts": {}
            }
            
            # Database statistics from CanaryDB
            if app.monitor_server and app.monitor_server.db:
                stats["db"] = app.monitor_server.db.get_stats()
            
            # Monitor server statistics
            if app.monitor_server:
                stats["monitor"] = app.monitor_server.get_statistics()
            
            # Alert manager statistics
            if app.alert_manager:
                stats["alerts"] = app.alert_manager.get_statistics()
            
            return jsonify(stats)
        
        except Exception as e:
            logger.error(f"[Dashboard] Error fetching stats: {e}")
        
        return jsonify({"error": "Database error"}), 500
    
    # =====================================
    # SocketIO Events
    # =====================================
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client WebSocket connection"""
        logger.debug("[Dashboard] Client connected via WebSocket")
        emit('connection_response', {
            'status': 'connected',
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'Connected to Canary-Net Monitor'
        })
        
        # Send current stats to newly connected client
        try:
            if app.monitor_server and app.monitor_server.db:
                stats = app.monitor_server.db.get_stats()
                emit('stats_update', stats)
        except Exception as e:
            logger.debug(f"[Dashboard] Error sending initial stats: {e}")
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client WebSocket disconnection"""
        logger.debug("[Dashboard] Client disconnected")
    
    @socketio.on('subscribe_alerts')
    def handle_subscribe_alerts():
        """Handle client subscription to live alerts"""
        logger.debug("[Dashboard] Client subscribed to live alerts")
        emit('subscription_response', {
            'status': 'subscribed',
            'channel': 'alerts',
            'timestamp': datetime.utcnow().isoformat()
        })
    
    @socketio.on('request_stats')
    def handle_request_stats():
        """Handle stats request from client"""
        try:
            stats = {
                "timestamp": datetime.utcnow().isoformat(),
                "db": {},
                "monitor": {},
                "alerts": {}
            }
            
            if app.monitor_server and app.monitor_server.db:
                stats["db"] = app.monitor_server.db.get_stats()
            
            if app.monitor_server:
                stats["monitor"] = app.monitor_server.get_statistics()
            
            if app.alert_manager:
                stats["alerts"] = app.alert_manager.get_statistics()
            
            emit('stats_update', stats)
            logger.debug("[Dashboard] Sent stats update to client")
        
        except Exception as e:
            logger.error(f"[Dashboard] Error sending stats: {e}")
            emit('error', {'message': str(e)})
    
    @socketio.on('new_alert')
    def handle_new_alert(data):
        """
        Handle new alert from monitor server
        Broadcasts to all connected clients
        """
        try:
            logger.debug(f"[Dashboard] Received new_alert event: {data.get('alert_id', 'unknown')}")
            
            # Broadcast to all connected clients
            socketio.emit(
                'alert_notification',
                data,
                broadcast=True,
                namespace='/'
            )
            
            logger.debug("[Dashboard] Broadcasted alert to all clients")
        
        except Exception as e:
            logger.error(f"[Dashboard] Error handling new_alert: {e}")
    
    @socketio.on_error_default
    def default_error_handler(e):
        """Handle SocketIO errors"""
        logger.error(f"[Dashboard] SocketIO error: {e}")
        emit('error', {'message': 'Server error occurred'})
    
    return app, socketio


def inject_emit_callback(app, socketio):
    """
    Create a callback function for MonitorServer to emit SocketIO events
    
    Args:
        app: Flask app instance
        socketio: SocketIO instance
    
    Returns:
        Callback function(event_name, alert_data)
    """
    def emit_alert(event_name, alert_data):
        """
        Emit alert to all connected clients
        
        Args:
            event_name: Name of the event (e.g., 'new_alert')
            alert_data: Alert dictionary to emit
        """
        try:
            with app.app_context():
                socketio.emit(
                    event_name,
                    alert_data,
                    broadcast=True,
                    namespace='/'
                )
            logger.debug(f"[Dashboard] Emitted {event_name} to clients")
        except Exception as e:
            logger.error(f"[Dashboard] Failed to emit event: {e}")
    
    return emit_alert


if __name__ == '__main__':
    app, socketio = create_app()
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)
