/**
 * Canary-Net Dashboard JavaScript
 * Real-time alert monitoring with SocketIO and REST API
 */

// SocketIO Connection
const socket = io({
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    reconnectionAttempts: 5
});

// State
let allAlerts = [];
let filteredAlerts = [];
let currentCanaries = new Set();
const MAX_ALERTS_DISPLAY = 100;

// =====================================
// SocketIO Event Handlers
// =====================================

socket.on('connect', () => {
    console.log('[Dashboard] Connected to server');
    updateStatus('connected');
    socket.emit('subscribe_alerts');
    loadAlerts();
    requestStats();
});

socket.on('disconnect', () => {
    console.log('[Dashboard] Disconnected from server');
    updateStatus('disconnected');
});

socket.on('connection_response', (data) => {
    console.log('[Dashboard] Connection response:', data);
});

socket.on('alert_notification', (alert) => {
    console.log('[Dashboard] New alert received:', alert);
    prependAlert(alert);
    requestStats();
});

socket.on('stats_update', (stats) => {
    console.log('[Dashboard] Stats update:', stats);
    updateStats(stats);
});

socket.on('subscription_response', (data) => {
    console.log('[Dashboard] Subscription response:', data);
});

socket.on('error', (error) => {
    console.error('[Dashboard] Error:', error);
});

// =====================================
// Status Management
// =====================================

function updateStatus(status) {
    const statusIndicator = document.getElementById('status');
    const statusDot = statusIndicator.querySelector('.status-dot');
    const statusText = statusIndicator.querySelector('.status-text');

    if (status === 'connected') {
        statusDot.classList.remove('disconnected');
        statusDot.classList.add('connected');
        statusText.textContent = 'Connected';
    } else {
        statusDot.classList.remove('connected');
        statusDot.classList.add('disconnected');
        statusText.textContent = 'Disconnected';
    }
}

// =====================================
// Alert Loading & Display
// =====================================

function loadAlerts() {
    console.log('[Dashboard] Loading alerts...');
    
    fetch('/api/alerts?limit=100&hours=24')
        .then(response => response.json())
        .then(data => {
            console.log('[Dashboard] Loaded', data.alerts.length, 'alerts');
            allAlerts = data.alerts || [];
            applyFilters();
            updateCanaryFilter();
        })
        .catch(error => console.error('[Dashboard] Error loading alerts:', error));
}

function prependAlert(alert) {
    allAlerts.unshift(alert);
    
    // Keep only latest
    if (allAlerts.length > MAX_ALERTS_DISPLAY) {
        allAlerts = allAlerts.slice(0, MAX_ALERTS_DISPLAY);
    }
    
    applyFilters();
    updateCanaryFilter();
}

function applyFilters() {
    const searchTerm = document.getElementById('filter-search').value.toLowerCase();
    const canaryFilter = document.getElementById('filter-canary').value;
    
    filteredAlerts = allAlerts.filter(alert => {
        // Search filter
        if (searchTerm) {
            const matches = 
                (alert.attacker_ip && alert.attacker_ip.includes(searchTerm)) ||
                (alert.canary_name && alert.canary_name.toLowerCase().includes(searchTerm)) ||
                (alert.behavior && alert.behavior.toLowerCase().includes(searchTerm));
            
            if (!matches) return false;
        }
        
        // Canary filter
        if (canaryFilter && alert.canary_name !== canaryFilter) {
            return false;
        }
        
        return true;
    });
    
    renderAlerts();
}

function updateCanaryFilter() {
    const canaries = new Set(allAlerts.map(a => a.canary_name).filter(Boolean));
    
    // Only update if changed
    if (canaries.size === currentCanaries.size && 
        [...canaries].every(c => currentCanaries.has(c))) {
        return;
    }
    
    currentCanaries = canaries;
    
    const select = document.getElementById('filter-canary');
    const currentValue = select.value;
    
    select.innerHTML = '<option value="">All Canaries</option>';
    
    [...canaries].sort().forEach(canary => {
        const option = document.createElement('option');
        option.value = canary;
        option.textContent = canary;
        select.appendChild(option);
    });
    
    select.value = currentValue;
}

function renderAlerts() {
    const container = document.getElementById('alerts-container');

    if (filteredAlerts.length === 0) {
        container.innerHTML = '<div class="empty-state">No alerts found</div>';
        return;
    }

    container.innerHTML = filteredAlerts
        .map(alert => createAlertElement(alert))
        .join('');
    
    // Attach click handlers
    document.querySelectorAll('.btn-detail').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            showAlertDetail(btn.dataset.alertId);
        });
    });
    
    document.querySelectorAll('.btn-acknowledge').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            acknowledgeAlert(btn.dataset.alertId);
        });
    });
}

function createAlertElement(alert) {
    const timestamp = formatTime(alert.timestamp);
    const canary = escapeHtml(alert.canary_name || 'UNKNOWN');
    const attacker = escapeHtml(alert.attacker_ip || 'UNKNOWN');
    const port = escapeHtml(String(alert.port || '?'));
    const attackerPort = escapeHtml(String(alert.attacker_port || '?'));
    const behavior = escapeHtml(String(alert.behavior || 'N/A')).substring(0, 100);
    const isAck = alert.acknowledged ? 'acknowledged' : '';
    const ackBadge = alert.acknowledged ? '✓ Acknowledged' : '🔴 Pending';
    const ackBadgeClass = alert.acknowledged ? '' : 'unacknowledged';

    return `
        <div class="alert-item ${isAck}">
            <div class="alert-main">
                <div class="alert-header">
                    <div class="alert-canary">🎯 ${canary}</div>
                    <div class="alert-time">${timestamp}</div>
                </div>
                <div class="alert-body">
                    <div class="alert-detail">
                        <div class="alert-detail-label">Source</div>
                        <div class="alert-detail-value">${attacker}:${attackerPort}</div>
                    </div>
                    <div class="alert-detail">
                        <div class="alert-detail-label">Target Port</div>
                        <div class="alert-detail-value">${port}</div>
                    </div>
                </div>
                <div class="alert-behavior">📋 ${behavior}...</div>
                <div class="alert-actions">
                    <button class="btn-small btn-detail" data-alert-id="${alert.alert_id}">Details</button>
                    ${!alert.acknowledged ? 
                        `<button class="btn-small btn-acknowledge" data-alert-id="${alert.alert_id}">Acknowledge</button>` 
                        : ''}
                </div>
            </div>
            <div class="alert-status">
                <span class="alert-badge ${ackBadgeClass}">${ackBadge}</span>
            </div>
        </div>
    `;
}

function showAlertDetail(alertId) {
    const alert = allAlerts.find(a => a.alert_id === alertId);
    if (!alert) return;

    const modal = document.getElementById('alert-modal');
    const body = document.getElementById('modal-body');
    
    body.innerHTML = `
        <p>
            <label>Alert ID</label>
            <div class="value">${escapeHtml(alert.alert_id)}</div>
        </p>
        <p>
            <label>Canary Name</label>
            <div class="value">${escapeHtml(alert.canary_name || 'N/A')}</div>
        </p>
        <p>
            <label>Attacker IP</label>
            <div class="value">${escapeHtml(alert.attacker_ip || 'N/A')}</div>
        </p>
        <p>
            <label>Attacker Port</label>
            <div class="value">${escapeHtml(String(alert.attacker_port || 'N/A'))}</div>
        </p>
        <p>
            <label>Target Port</label>
            <div class="value">${escapeHtml(String(alert.port || 'N/A'))}</div>
        </p>
        <p>
            <label>Behavior</label>
            <div class="value">${escapeHtml(alert.behavior || 'N/A')}</div>
        </p>
        <p>
            <label>Timestamp</label>
            <div class="value">${escapeHtml(alert.timestamp || 'N/A')}</div>
        </p>
        <p>
            <label>Fake Data Touched</label>
            <div class="value">${escapeHtml(alert.fake_data_touched || 'false')}</div>
        </p>
        <p>
            <label>Acknowledged</label>
            <div class="value">${alert.acknowledged ? 'Yes' : 'No'}</div>
        </p>
    `;
    
    modal.style.display = 'flex';
}

function acknowledgeAlert(alertId) {
    console.log('[Dashboard] Acknowledging alert:', alertId);
    
    fetch(`/api/acknowledge/${alertId}`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            console.log('[Dashboard] Alert acknowledged');
            
            // Update local alert
            const alert = allAlerts.find(a => a.alert_id === alertId);
            if (alert) {
                alert.acknowledged = true;
            }
            
            renderAlerts();
            requestStats();
        })
        .catch(error => console.error('[Dashboard] Error acknowledging alert:', error));
}

// =====================================
// Statistics Management
// =====================================

function updateStats(stats) {
    try {
        const db = stats.db || {};
        
        document.getElementById('stat-total').textContent = db.total || 0;
        document.getElementById('stat-unack').textContent = db.unacknowledged || 0;
        document.getElementById('stat-24h').textContent = db.last_24h || 0;
        document.getElementById('stat-canaries').textContent = Object.keys(db.by_canary || {}).length;
    } catch (error) {
        console.error('[Dashboard] Error updating stats:', error);
    }
}

function requestStats() {
    socket.emit('request_stats');
}

// =====================================
// Event Listeners
// =====================================

document.getElementById('filter-search').addEventListener('input', applyFilters);
document.getElementById('filter-canary').addEventListener('change', applyFilters);
document.getElementById('btn-refresh').addEventListener('click', loadAlerts);

// Modal close
document.querySelector('.modal-close').addEventListener('click', () => {
    document.getElementById('alert-modal').style.display = 'none';
});

document.getElementById('alert-modal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('alert-modal')) {
        document.getElementById('alert-modal').style.display = 'none';
    }
});

// =====================================
// Utility Functions
// =====================================

function formatTime(isoString) {
    try {
        const date = new Date(isoString);
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        return `${hours}:${minutes}:${seconds}`;
    } catch {
        return isoString || 'N/A';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// =====================================
// Initialization
// =====================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('[Dashboard] Initialized');
    loadAlerts();
    
    // Request stats every 10 seconds
    setInterval(requestStats, 10000);
});

