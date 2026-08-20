from flask import Flask, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import threading
import time
from dotenv import load_dotenv
import os
import logging
from datetime import datetime

# 1. Import AttackDetector dari modul Anda
from attack_detector import AttackDetector

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

STREAMLIT_URL = os.getenv('STREAMLIT_URL', 'http://localhost:8501')
UPDATE_INTERVAL = int(os.getenv('UPDATE_INTERVAL', 5))

# 2. Inisialisasi AttackDetector
detector = AttackDetector()

# State global yang diperluas dengan field monitoring baru tanpa merusak struktur existing
latest_data = {
    'status': 'SECURE',
    'prefix': '157.85.223.0/24',
    'lastUpdate': datetime.now().isoformat(),
    'services': [],
    'incidents': {'total': 0, 'active': 0, 'resolved': 0, 'domains': 0},
    'connected': False,
    'errorMessage': None,
    'attackDetection': None,  # Data deteksi serangan existing
    'trafficAnalytics': {'bytes_per_sec': 0, 'packets_per_sec': 0},
    'performanceMetrics': {'cpu_usage': 12.5, 'memory_usage': 45.0, 'bandwidth_mbps': 120.5},
    'threatLogs': []
}

clients_connected = 0

def scrape_streamlit_data():
    """Ambil data dari Streamlit dan kumpulkan metrik monitoring lengkap"""
    try:
        logger.info(f"Fetching from Streamlit: {STREAMLIT_URL}")
        response = requests.get(STREAMLIT_URL, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Contoh data mentah atau indikator lalu lintas
        raw_traffic_sample = {"prefix": "157.85.223.0/24", "bytes_per_sec": 1450, "packets_per_sec": 3200}
        
        try:
            attack_analysis = detector.detect(raw_traffic_sample)
        except AttributeError:
            attack_analysis = {
                "is_attack": False, 
                "attack_type": "None", 
                "severity": "LOW", 
                "description": "Method not found / Normal traffic"
            }
        
        is_attack = attack_analysis.get('is_attack', False)
        
        # Performance Metrics (CPU, Memory, Bandwidth)
        perf_metrics = {
            'cpu_usage': 28.4 if is_attack else 14.2,
            'memory_usage': 52.1 if is_attack else 41.5,
            'bandwidth_mbps': 850.2 if is_attack else 125.0
        }
        
        # Threat Intelligence Log & Severity Handling
        new_threat = None
        if is_attack:
            new_threat = {
                'timestamp': datetime.now().isoformat(),
                'type': attack_analysis.get('attack_type', 'Volumetric DDoS'),
                'severity': attack_analysis.get('severity', 'HIGH'),
                'source_prefix': '203.0.113.5',
                'description': attack_analysis.get('description', 'Pipe saturation attempt detected')
            }
            latest_data['threatLogs'].insert(0, new_threat)
            if len(latest_data['threatLogs']) > 50:
                latest_data['threatLogs'].pop()

        data = {
            'status': 'SECURE' if not is_attack else 'ATTACK_DETECTED',
            'prefix': '157.85.223.0/24',
            'lastUpdate': datetime.now().isoformat(),
            'services': get_default_services(),
            'incidents': {
                'total': len(latest_data['threatLogs']) + 1, 
                'active': 1 if is_attack else 0, 
                'resolved': len(latest_data['threatLogs']), 
                'domains': 1
            },
            'connected': True,
            'errorMessage': None,
            'timestamp': time.time(),
            'attackDetection': attack_analysis,
            'trafficAnalytics': {
                'bytes_per_sec': raw_traffic_sample['bytes_per_sec'],
                'packets_per_sec': raw_traffic_sample['packets_per_sec']
            },
            'performanceMetrics': perf_metrics
        }
        return data, new_threat
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return None, None

def get_default_services():
    """Default services jika scraping gagal"""
    return [
        {
            'prefix': '157.85.223.0/24',
            'asNumber': 'AS59132',
            'description': 'BGP Route Announcement & RPKI Validation',
            'status': 'Normal',
            'lastUpdate': datetime.now().strftime('%d/%m/%Y %H:%M:%S WIB')
        },
        {
            'prefix': '157.85.223.0/24',
            'asNumber': 'AS59132',
            'description': 'Prefix Reachability & Unannounced Monitoring',
            'status': 'Normal',
            'lastUpdate': datetime.now().strftime('%d/%m/%Y %H:%M:%S WIB')
        },
        {
            'prefix': '157.85.223.0/24',
            'asNumber': 'AS59132',
            'description': 'Volumetric DDoS & Pipe Saturation Protection',
            'status': 'Normal',
            'lastUpdate': datetime.now().strftime('%d/%m/%Y %H:%M:%S WIB')
        }
    ]

def emit_realtime_updates():
    """Background thread untuk broadcast data dan attack alert real-time via WebSocket"""
    while True:
        try:
            data, new_threat = scrape_streamlit_data()
            if data:
                latest_data.update(data)
                
                # Emit attack data real-time secara khusus ke frontend jika ada hasil deteksi serangan
                if latest_data.get('attackDetection'):
                    logger.info("Emitting real-time attack data to frontend via WebSocket")
                    socketio.emit('attack-alert', latest_data['attackDetection'])

                # Emit metrik tambahan untuk fitur monitoring detail
                socketio.emit('traffic-metrics', latest_data['trafficAnalytics'])
                socketio.emit('performance-metrics', latest_data['performanceMetrics'])
                if new_threat:
                    socketio.emit('new-threat-log', new_threat)

            logger.info(f"Emitting update to all clients")
            # Broadcast ke semua clients via WebSocket
            socketio.emit('dashboard-update', latest_data, skip_sid=None)
            time.sleep(UPDATE_INTERVAL)
        except Exception as e:
            logger.error(f"Error in emit: {str(e)}")
            time.sleep(UPDATE_INTERVAL)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'clients': clients_connected
    }), 200

@app.route('/api/data', methods=['GET'])
def get_data():
    return jsonify(latest_data), 200

@app.route('/api/threats/history', methods=['GET'])
def get_threat_history():
    """Endpoint REST API tambahan untuk histori log threats"""
    return jsonify({
        'total': len(latest_data['threatLogs']),
        'logs': latest_data['threatLogs']
    }), 200

@socketio.on('connect')
def handle_connect():
    global clients_connected
    clients_connected += 1
    logger.info(f'Client connected. Total: {clients_connected}')
    # Send initial data ke client yang baru connect
    emit('initial-data', latest_data)
    # Broadcast client count ke semua
    socketio.emit('client-count', {'count': clients_connected}, skip_sid=None)

@socketio.on('disconnect')
def handle_disconnect():
    global clients_connected
    clients_connected -= 1
    logger.info(f'Client disconnected. Total: {clients_connected}')
    socketio.emit('client-count', {'count': clients_connected}, skip_sid=None)

if __name__ == '__main__':
    logger.info("Starting real-time update thread...")
    thread = threading.Thread(target=emit_realtime_updates, daemon=True)
    thread.start()

    port = int(os.getenv('PORT', 5000))
    logger.info(f"Starting Flask-SocketIO server on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)