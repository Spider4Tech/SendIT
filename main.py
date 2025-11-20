from flask import Flask, render_template, request, make_response
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import secrets
import time
import hmac
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
CORS(app, resources={r"*": {"origins": ["http://localhost:3000", "http://localhost:5000"]}})
socketio = SocketIO(app, cors_allowed_origins=["http://localhost:3000", "http://localhost:5000", "*"], max_size=500 * 1024 * 1024, ping_timeout=120, ping_interval=25)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sendit_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

active_transfers = {}
connection_attempts = defaultdict(list)
room_creation_times = {}
revoked_rooms = set()
chunk_cache = defaultdict(lambda: {'chunks': {}, 'last_access': time.time()})

ROOM_TIMEOUT = 600
MAX_ATTEMPTS_PER_IP = 10
ATTEMPT_WINDOW = 60
ROOM_ID_LENGTH = 32
MAX_CHUNK_SIZE = 150 * 1024
MIN_CHUNK_SIZE = 1024
MAX_CHUNKS_PER_TRANSFER = 5000
CACHE_CLEANUP_INTERVAL = 60
IP_BAN_THRESHOLD = 50
IP_BAN_WINDOW = 3600

def get_client_ip():
    if request.environ.get('HTTP_CF_CONNECTING_IP'):
        return request.environ.get('HTTP_CF_CONNECTING_IP')
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ.get('HTTP_X_FORWARDED_FOR').split(',')[0].strip()
    return request.environ.get('REMOTE_ADDR', 'unknown')

def cleanup_old_rooms():
    while True:
        time.sleep(CACHE_CLEANUP_INTERVAL)
        current_time = time.time()
        
        for room_id in list(room_creation_times.keys()):
            if current_time - room_creation_times[room_id] > ROOM_TIMEOUT:
                if room_id in active_transfers:
                    logger.info(f'Cleaning up expired transfer: {room_id}')
                    del active_transfers[room_id]
                revoked_rooms.discard(room_id)
                del room_creation_times[room_id]
        
        for room_id in list(chunk_cache.keys()):
            if current_time - chunk_cache[room_id]['last_access'] > ROOM_TIMEOUT:
                del chunk_cache[room_id]

def cleanup_banned_ips():
    while True:
        time.sleep(CACHE_CLEANUP_INTERVAL)
        current_time = time.time()
        ips_to_check = list(connection_attempts.keys())
        
        for ip in ips_to_check:
            connection_attempts[ip] = [
                (t, failed) for t, failed in connection_attempts[ip]
                if current_time - t < IP_BAN_WINDOW
            ]

cleanup_thread = threading.Thread(target=cleanup_old_rooms, daemon=True)
cleanup_thread.start()
ban_thread = threading.Thread(target=cleanup_banned_ips, daemon=True)
ban_thread.start()

def is_ip_banned(ip_address):
    current_time = time.time()
    connection_attempts[ip_address] = [
        (t, failed) for t, failed in connection_attempts[ip_address]
        if current_time - t < IP_BAN_WINDOW
    ]
    
    failed_count = sum(1 for _, failed in connection_attempts[ip_address] if failed)
    return failed_count >= IP_BAN_THRESHOLD

def check_rate_limit(ip_address):
    current_time = time.time()
    
    if is_ip_banned(ip_address):
        logger.warning(f'Blocked banned IP: {ip_address}')
        return False
    
    connection_attempts[ip_address] = [
        (t, failed) for t, failed in connection_attempts[ip_address]
        if current_time - t < ATTEMPT_WINDOW
    ]
    
    if len(connection_attempts[ip_address]) >= MAX_ATTEMPTS_PER_IP:
        for i, (_, failed) in enumerate(connection_attempts[ip_address]):
            if not failed:
                connection_attempts[ip_address][i] = (connection_attempts[ip_address][i][0], True)
        logger.warning(f'Rate limit exceeded for IP: {ip_address}')
        return False
    
    connection_attempts[ip_address].append((current_time, False))
    return True

def generate_hmac(data, room_id):
    room_secret = app.config['SECRET_KEY'] + room_id
    return hmac.new(
        room_secret.encode() if isinstance(room_secret, str) else room_secret,
        data.encode() if isinstance(data, str) else data,
        hashlib.sha256
    ).hexdigest()

def verify_hmac(data, provided_hmac, room_id):
    expected_hmac = generate_hmac(data, room_id)
    return hmac.compare_digest(expected_hmac, provided_hmac)

def sanitize_string(value, max_length=1000):
    if not isinstance(value, str):
        return None
    return value[:max_length]

def validate_chunk_data(chunk, size):
    if not isinstance(chunk, str) or not chunk:
        return False
    if size < MIN_CHUNK_SIZE or size > MAX_CHUNK_SIZE:
        return False
    return True

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-hashes'; "
        "style-src 'self' 'unsafe-inline' 'unsafe-hashes'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data: blob:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'none'; "
        "frame-ancestors 'none'; "
        "upgrade-insecure-requests"
    )
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'

    return response

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    client_ip = get_client_ip()
    
    if not check_rate_limit(client_ip):
        logger.warning(f'Connection rejected for IP: {client_ip}')
        return False
    
    logger.info(f'Client connected: {client_ip}, SID: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f'Client disconnected: SID: {request.sid}')
    for room_id, transfer in list(active_transfers.items()):
        if request.sid in transfer.get('participants', []):
            transfer['participants'].remove(request.sid)
            if len(transfer['participants']) == 0:
                logger.info(f'Cleaning up transfer after disconnect: {room_id}')
                del active_transfers[room_id]
                revoked_rooms.discard(room_id)
                if room_id in room_creation_times:
                    del room_creation_times[room_id]

@socketio.on('create_room')
def handle_create_room(data):
    client_ip = get_client_ip()
    
    if not check_rate_limit(client_ip):
        logger.warning(f'Room creation rejected for IP: {client_ip}')
        emit('error', {'message': 'Trop de tentatives. Veuillez réessayer plus tard.'})
        return
    
    try:
        if not isinstance(data, dict):
            data = {}
        
        room_id = secrets.token_urlsafe(ROOM_ID_LENGTH)
        
        active_transfers[room_id] = {
            'participants': [request.sid],
            'file_info': None,
            'file_hash': None,
            'sender': request.sid,
            'created_at': time.time(),
            'creator_ip': client_ip,
            'chunk_count': 0
        }
        
        room_creation_times[room_id] = time.time()
        
        join_room(room_id)
        
        emit('room_created', {
            'room_id': room_id
        })
        
        logger.info(f'Room created: {room_id} by {client_ip}')
    except Exception as e:
        logger.error(f'Error creating room: {str(e)}')
        emit('error', {'message': 'Erreur lors de la création de la salle'})

@socketio.on('join_room')
def handle_join_room(data):
    try:
        room_id = sanitize_string(data.get('room_id')) if isinstance(data, dict) else None
        client_ip = get_client_ip()
        
        if not room_id:
            emit('error', {'message': 'ID de salle invalide'})
            return
        
        if not check_rate_limit(client_ip):
            logger.warning(f'Join room rejected for IP: {client_ip}')
            emit('error', {'message': 'Trop de tentatives. Veuillez réessayer plus tard.'})
            return
        
        if room_id in revoked_rooms:
            logger.warning(f'Attempted to join revoked room: {room_id} from {client_ip}')
            emit('error', {'message': 'Salle révoquée'})
            return
        
        if room_id not in active_transfers:
            logger.warning(f'Join attempt to non-existent room: {room_id}')
            emit('error', {'message': 'Salle introuvable ou expirée'})
            return
        
        transfer_data = active_transfers[room_id]
        
        if len(transfer_data['participants']) >= 2:
            logger.warning(f'Room full: {room_id}')
            emit('error', {'message': 'Salle complète - transfert déjà en cours'})
            return
        
        current_time = time.time()
        if current_time - transfer_data['created_at'] > ROOM_TIMEOUT:
            logger.info(f'Room expired: {room_id}')
            del active_transfers[room_id]
            revoked_rooms.discard(room_id)
            if room_id in room_creation_times:
                del room_creation_times[room_id]
            emit('error', {'message': 'Salle expirée'})
            return
        
        transfer_data['participants'].append(request.sid)
        transfer_data['receiver'] = request.sid
        transfer_data['receiver_ip'] = client_ip
        
        join_room(room_id)
        
        emit('room_joined', {})
        emit('peer_connected', {}, to=transfer_data['sender'])
        
        logger.info(f'Client {client_ip} joined room: {room_id}')
    except Exception as e:
        logger.error(f'Error joining room: {str(e)}')
        emit('error', {'message': 'Erreur lors de la connexion à la salle'})

@socketio.on('file_info')
def handle_file_info(data):
    try:
        room_id = sanitize_string(data.get('room_id')) if isinstance(data, dict) else None
        encrypted_metadata = sanitize_string(data.get('encrypted_metadata')) if isinstance(data, dict) else None
        
        if not room_id or not encrypted_metadata:
            emit('error', {'message': 'Données invalides'})
            return
        
        if room_id not in active_transfers:
            logger.warning(f'File info for non-existent room: {room_id}')
            emit('error', {'message': 'Salle introuvable'})
            return
        
        transfer_data = active_transfers[room_id]
        
        if request.sid != transfer_data.get('sender'):
            logger.warning(f'Unauthorized file info attempt in room: {room_id}')
            emit('error', {'message': 'Non autorisé'})
            return
        
        if len(encrypted_metadata) > 10000:
            logger.warning(f'File info too large in room: {room_id}')
            emit('error', {'message': 'Métadonnées trop volumineuses'})
            return
        
        transfer_data['encrypted_metadata'] = encrypted_metadata
        
        receiver = transfer_data.get('receiver')
        if receiver:
            emit('file_info', {
                'encrypted_metadata': encrypted_metadata
            }, to=receiver)
    except Exception as e:
        logger.error(f'Error handling file info: {str(e)}')
        emit('error', {'message': 'Erreur lors de la réception des métadonnées'})

@socketio.on('file_chunk')
def handle_file_chunk(data):
    try:
        room_id = sanitize_string(data.get('room_id')) if isinstance(data, dict) else None
        chunk = sanitize_string(data.get('chunk'), max_length=MAX_CHUNK_SIZE) if isinstance(data, dict) else None
        sequence = data.get('sequence') if isinstance(data, dict) else None
        index = data.get('index') if isinstance(data, dict) else None
        is_last = data.get('is_last', False) if isinstance(data, dict) else False
        chunk_hash = sanitize_string(data.get('chunk_hash')) if isinstance(data, dict) else None
        
        if not room_id or not chunk or sequence is None or index is None:
            logger.warning(f'Invalid chunk data for room: {room_id}')
            emit('error', {'message': 'Données de chunk invalides'})
            return
        
        if room_id not in active_transfers:
            logger.warning(f'Chunk for non-existent room: {room_id}')
            return
        
        transfer_data = active_transfers[room_id]
        
        if request.sid != transfer_data.get('sender'):
            logger.warning(f'Unauthorized chunk attempt in room: {room_id}')
            return
        
        if not isinstance(chunk, str) or len(chunk) == 0:
            logger.warning(f'Invalid chunk format in room: {room_id}')
            emit('error', {'message': 'Chunk invalide'}, to=request.sid)
            return
        
        if transfer_data['chunk_count'] >= MAX_CHUNKS_PER_TRANSFER:
            logger.warning(f'Too many chunks in room: {room_id}')
            emit('error', {'message': 'Nombre de chunks dépassé'}, to=request.sid)
            return
        
        if not isinstance(sequence, int) or not isinstance(index, int):
            logger.warning(f'Invalid sequence/index in room: {room_id}')
            emit('error', {'message': 'Séquence invalide'}, to=request.sid)
            return
        
        if sequence < 0 or index < 0:
            logger.warning(f'Negative sequence/index in room: {room_id}')
            emit('error', {'message': 'Index invalide'}, to=request.sid)
            return
        
        transfer_data['chunk_count'] += 1
        chunk_cache[room_id]['last_access'] = time.time()
        chunk_cache[room_id]['chunks'][index] = chunk
        
        receiver = transfer_data.get('receiver')
        
        if receiver:
            emit('file_chunk', {
                'chunk': chunk,
                'sequence': sequence,
                'index': index,
                'is_last': is_last,
                'chunk_hash': chunk_hash
            }, to=receiver)
        
        logger.debug(f'Chunk {index} processed in room {room_id}')
    except Exception as e:
        logger.error(f'Error handling chunk: {str(e)}')
        emit('error', {'message': 'Erreur lors de la réception du chunk'}, to=request.sid)

@socketio.on('transfer_complete')
def handle_transfer_complete(data):
    try:
        room_id = sanitize_string(data.get('room_id')) if isinstance(data, dict) else None
        file_hash = sanitize_string(data.get('file_hash')) if isinstance(data, dict) else None
        
        if not room_id:
            logger.warning('Transfer complete with invalid room_id')
            return
        
        if room_id not in active_transfers:
            logger.warning(f'Transfer complete for non-existent room: {room_id}')
            return
        
        transfer_data = active_transfers[room_id]
        
        if file_hash:
            transfer_data['file_hash'] = file_hash
        
        for participant in transfer_data['participants']:
            emit('transfer_complete', {'file_hash': file_hash}, to=participant)
        
        logger.info(f'Transfer complete and room destroyed: {room_id}')
        
        del active_transfers[room_id]
        revoked_rooms.discard(room_id)
        if room_id in room_creation_times:
            del room_creation_times[room_id]
        if room_id in chunk_cache:
            del chunk_cache[room_id]
    except Exception as e:
        logger.error(f'Error completing transfer: {str(e)}')

@socketio.on('transfer_progress')
def handle_transfer_progress(data):
    try:
        room_id = sanitize_string(data.get('room_id')) if isinstance(data, dict) else None
        progress = data.get('progress') if isinstance(data, dict) else None
        
        if room_id not in active_transfers:
            return
        
        if progress is None or not isinstance(progress, (int, float)):
            logger.warning(f'Invalid progress value for room: {room_id}')
            return
        
        if progress < 0 or progress > 100:
            logger.warning(f'Progress out of range for room: {room_id}')
            return
        
        transfer_data = active_transfers[room_id]
        sender = transfer_data.get('sender')
        
        if request.sid != sender:
            emit('transfer_progress', {'progress': progress}, to=sender)
    except Exception as e:
        logger.error(f'Error updating transfer progress: {str(e)}')

@socketio.on('revoke_room')
def handle_revoke_room(data):
    try:
        room_id = sanitize_string(data.get('room_id')) if isinstance(data, dict) else None
        
        if not room_id:
            emit('error', {'message': 'ID de salle invalide'})
            return
        
        if room_id not in active_transfers:
            emit('error', {'message': 'Salle introuvable'})
            return
        
        transfer_data = active_transfers[room_id]
        
        if request.sid != transfer_data.get('sender'):
            logger.warning(f'Unauthorized revoke attempt in room: {room_id}')
            emit('error', {'message': 'Non autorisé'})
            return
        
        revoked_rooms.add(room_id)
        logger.info(f'Room revoked: {room_id}')
        emit('room_revoked', {}, to=transfer_data.get('receiver') or request.sid)
    except Exception as e:
        logger.error(f'Error revoking room: {str(e)}')
        emit('error', {'message': 'Erreur lors de la révocation'})

@socketio.on('request_chunk_retry')
def handle_request_chunk_retry(data):
    try:
        room_id = sanitize_string(data.get('room_id')) if isinstance(data, dict) else None
        chunk_index = data.get('chunk_index') if isinstance(data, dict) else None
        
        if not room_id or chunk_index is None:
            logger.warning('Invalid retry request')
            return
        
        if room_id not in active_transfers:
            logger.warning(f'Retry request for non-existent room: {room_id}')
            return
        
        transfer_data = active_transfers[room_id]
        sender = transfer_data.get('sender')
        
        if request.sid != transfer_data.get('receiver'):
            logger.warning(f'Unauthorized retry request in room: {room_id}')
            return
        
        if not isinstance(chunk_index, int) or chunk_index < 0:
            logger.warning(f'Invalid chunk index in retry request: {chunk_index}')
            return
        
        logger.info(f'Chunk retry requested in room {room_id} for chunk {chunk_index}')
        emit('request_chunk_retry', {'chunk_index': chunk_index}, to=sender)
    except Exception as e:
        logger.error(f'Error handling retry request: {str(e)}')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=False)
