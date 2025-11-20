from flask import Flask, render_template, request, make_response
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import secrets
import time
from collections import defaultdict
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", max_size=500 * 1024 * 1024, ping_timeout=120, ping_interval=25)

active_transfers = {}
connection_attempts = defaultdict(list)
room_creation_times = {}

ROOM_TIMEOUT = 600
MAX_ATTEMPTS_PER_IP = 10
ATTEMPT_WINDOW = 60
ROOM_ID_LENGTH = 32

def cleanup_old_rooms():
    while True:
        time.sleep(30)
        current_time = time.time()
        for room_id in list(room_creation_times.keys()):
            if current_time - room_creation_times[room_id] > ROOM_TIMEOUT:
                if room_id in active_transfers:
                    del active_transfers[room_id]
                del room_creation_times[room_id]

cleanup_thread = threading.Thread(target=cleanup_old_rooms, daemon=True)
cleanup_thread.start()

def check_rate_limit(ip_address):
    current_time = time.time()
    connection_attempts[ip_address] = [
        t for t in connection_attempts[ip_address] 
        if current_time - t < ATTEMPT_WINDOW
    ]
    
    if len(connection_attempts[ip_address]) >= MAX_ATTEMPTS_PER_IP:
        return False
    
    connection_attempts[ip_address].append(current_time)
    return True

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
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
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
    
    if not check_rate_limit(client_ip):
        return False

@socketio.on('disconnect')
def handle_disconnect():
    for room_id, transfer in list(active_transfers.items()):
        if request.sid in transfer.get('participants', []):
            transfer['participants'].remove(request.sid)
            if len(transfer['participants']) == 0:
                del active_transfers[room_id]
                if room_id in room_creation_times:
                    del room_creation_times[room_id]

@socketio.on('create_room')
def handle_create_room(data):
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
    
    if not check_rate_limit(client_ip):
        emit('error', {'message': 'Trop de tentatives. Veuillez réessayer plus tard.'})
        return
    
    room_id = secrets.token_urlsafe(ROOM_ID_LENGTH)
    
    active_transfers[room_id] = {
        'participants': [request.sid],
        'file_info': None,
        'sender': request.sid,
        'created_at': time.time(),
        'creator_ip': client_ip
    }
    
    room_creation_times[room_id] = time.time()
    
    join_room(room_id)
    
    emit('room_created', {
        'room_id': room_id
    })
    
    print(f'Room created: {room_id} by {client_ip}')

@socketio.on('join_room')
def handle_join_room(data):
    room_id = data.get('room_id')
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
    
    if not check_rate_limit(client_ip):
        emit('error', {'message': 'Trop de tentatives. Veuillez réessayer plus tard.'})
        return
    
    if room_id not in active_transfers:
        emit('error', {'message': 'Salle introuvable ou expirée'})
        return
    
    transfer_data = active_transfers[room_id]
    
    if len(transfer_data['participants']) >= 2:
        emit('error', {'message': 'Salle complète - transfert déjà en cours'})
        return
    
    current_time = time.time()
    if current_time - transfer_data['created_at'] > ROOM_TIMEOUT:
        del active_transfers[room_id]
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
    
    print(f'Client {client_ip} joined room: {room_id}')

@socketio.on('file_info')
def handle_file_info(data):
    room_id = data.get('room_id')
    
    if room_id not in active_transfers:
        emit('error', {'message': 'Salle introuvable'})
        return
    
    transfer_data = active_transfers[room_id]
    
    if request.sid != transfer_data.get('sender'):
        emit('error', {'message': 'Non autorisé'})
        return
    
    transfer_data['encrypted_metadata'] = data.get('encrypted_metadata')
    
    receiver = transfer_data.get('receiver')
    if receiver:
        emit('file_info', {
            'encrypted_metadata': data.get('encrypted_metadata')
        }, to=receiver)

@socketio.on('file_chunk')
def handle_file_chunk(data):
    room_id = data.get('room_id')
    
    if room_id not in active_transfers:
        return
    
    transfer_data = active_transfers[room_id]
    
    if request.sid != transfer_data.get('sender'):
        return
    
    chunk = data.get('chunk')
    if not chunk or not isinstance(chunk, str) or len(chunk) == 0:
        emit('error', {'message': 'Chunk invalide'}, to=request.sid)
        return
    
    receiver = transfer_data.get('receiver')
    
    if receiver:
        emit('file_chunk', {
            'chunk': chunk,
            'sequence': data.get('sequence'),
            'index': data.get('index'),
            'is_last': data.get('is_last', False)
        }, to=receiver)

@socketio.on('transfer_complete')
def handle_transfer_complete(data):
    room_id = data.get('room_id')
    
    if room_id in active_transfers:
        transfer_data = active_transfers[room_id]
        
        for participant in transfer_data['participants']:
            emit('transfer_complete', {}, to=participant)
        
        del active_transfers[room_id]
        if room_id in room_creation_times:
            del room_creation_times[room_id]
        
        print(f'Transfer complete and room destroyed: {room_id}')

@socketio.on('transfer_progress')
def handle_transfer_progress(data):
    room_id = data.get('room_id')
    progress = data.get('progress')
    
    if room_id in active_transfers:
        transfer_data = active_transfers[room_id]
        sender = transfer_data.get('sender')
        
        if request.sid != sender:
            emit('transfer_progress', {'progress': progress}, to=sender)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
