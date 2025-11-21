from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import secrets
import time
import hmac
import hashlib
import logging
from collections import defaultdict
import threading

# Configuration de l'application
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
# Limite globale de requête Flask (sécurité niveau HTTP)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 

# Configuration CORS stricte
CORS(app, resources={r"/*": {"origins": "*"}})

# Configuration SocketIO
# ping_timeout: Si pas de réponse en 60s, on coupe (détection client mort)
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    max_size=500 * 1024 * 1024, 
    ping_timeout=60, 
    ping_interval=25,
    async_mode='threading' # Ou 'eventlet'/'gevent' en prod pour la performance
)

# Logging structuré
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sendit_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- ÉTAT EN MÉMOIRE (VOLATILE) ---
# Seules les métadonnées de connexion sont stockées. 
# AUCUN contenu de fichier n'est stocké ici.
active_transfers = {}
connection_attempts = defaultdict(list)
room_creation_times = {}
revoked_rooms = set()

# --- CONSTANTES DE SÉCURITÉ ---
ROOM_TIMEOUT = 600                 # 10 minutes max par salle
MAX_ATTEMPTS_PER_IP = 5            # Durci : 5 essais max (anti-bruteforce)
ATTEMPT_WINDOW = 60                # Fenêtre de 1 minute
IP_BAN_THRESHOLD = 20              # Ban après 20 échecs globaux
IP_BAN_WINDOW = 3600               # Ban de 1 heure
ROOM_ID_LENGTH = 32                # Entropie élevée pour l'ID de salle
MAX_CHUNK_SIZE = 256 * 1024        # 256KB max par paquet (pour éviter DoS mémoire)
MAX_CHUNKS_PER_TRANSFER = 100000   # Limite théorique haute

# --- UTILITAIRES SÉCURITÉ ---

def get_client_ip():
    """Récupère l'IP réelle même derrière un proxy."""
    if request.environ.get('HTTP_CF_CONNECTING_IP'):
        return request.environ.get('HTTP_CF_CONNECTING_IP')
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ.get('HTTP_X_FORWARDED_FOR').split(',')[0].strip()
    return request.environ.get('REMOTE_ADDR', 'unknown')

def cleanup_worker():
    """Nettoyeur de fond pour les salles expirées et les IPs bannies."""
    while True:
        time.sleep(60)
        current_time = time.time()
        
        # 1. Nettoyage des salles expirées
        for room_id in list(room_creation_times.keys()):
            if current_time - room_creation_times[room_id] > ROOM_TIMEOUT:
                if room_id in active_transfers:
                    logger.info(f'Cleaning up expired transfer: {room_id}')
                    # Notifier les participants si encore connectés
                    socketio.emit('error', {'message': 'Session expirée'}, room=room_id)
                    del active_transfers[room_id]
                revoked_rooms.discard(room_id)
                del room_creation_times[room_id]
        
        # 2. Nettoyage des tentatives de connexion (Rate Limiting)
        ips_to_check = list(connection_attempts.keys())
        for ip in ips_to_check:
            # Garder seulement les tentatives récentes
            connection_attempts[ip] = [
                (t, failed) for t, failed in connection_attempts[ip]
                if current_time - t < IP_BAN_WINDOW
            ]
            if not connection_attempts[ip]:
                del connection_attempts[ip]

# Démarrage du thread de nettoyage
threading.Thread(target=cleanup_worker, daemon=True).start()

def check_rate_limit(ip_address):
    """Vérifie si l'IP abuse du service."""
    current_time = time.time()
    
    # Vérification BAN
    failed_count = sum(1 for _, failed in connection_attempts[ip_address] if failed)
    if failed_count >= IP_BAN_THRESHOLD:
        return False # BANNED
    
    # Nettoyage fenêtre glissante pour le rate limiting court terme
    connection_attempts[ip_address] = [
        (t, failed) for t, failed in connection_attempts[ip_address]
        if current_time - t < ATTEMPT_WINDOW
    ]
    
    # Vérification Rate Limit
    if len(connection_attempts[ip_address]) >= MAX_ATTEMPTS_PER_IP:
        # Marquer comme échoué pour potentiellement bannir
        connection_attempts[ip_address].append((current_time, True))
        logger.warning(f'Rate limit exceeded for IP: {ip_address}')
        return False
    
    connection_attempts[ip_address].append((current_time, False))
    return True

def sanitize_string(value, max_length=1000):
    """Nettoie les entrées textuelles."""
    if not isinstance(value, str):
        return None
    return value[:max_length]

# --- HEADERS HTTP DE SÉCURITÉ ---

@app.after_request
def set_security_headers(response):
    """Ajoute les en-têtes de sécurité modernes."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; "
        "script-src 'self' 'unsafe-inline'; " # Nécessaire pour socket.io parfois
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss: http: https:; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "base-uri 'self'; "
        "form-action 'none';"
    )
    return response

# --- ROUTES WEB ---

@app.route('/')
def index():
    return render_template('index.html')

# --- SOCKET IO EVENTS ---

@socketio.on('connect')
def handle_connect():
    client_ip = get_client_ip()
    if not check_rate_limit(client_ip):
        logger.warning(f'Connection rejected (Rate Limit): {client_ip}')
        return False # Reject connection
    logger.info(f'Client connected: {client_ip} ({request.sid})')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f'Client disconnected: {request.sid}')
    
    # Recherche des salles où ce client était actif
    for room_id, transfer in list(active_transfers.items()):
        if request.sid in transfer.get('participants', []):
            transfer['participants'].remove(request.sid)
            
            # Si c'est l'EXPÉDITEUR qui part, c'est critique -> Annuler transfert
            if request.sid == transfer.get('sender'):
                receiver = transfer.get('receiver')
                if receiver:
                    logger.warning(f'Sender disconnected during transfer: {room_id}')
                    emit('error', {'message': 'L\'expéditeur s\'est déconnecté. Transfert annulé.'}, to=receiver)
                    # Force disconnect logic/cleanup
                    del active_transfers[room_id]
            
            # Si la salle est vide, on nettoie
            elif len(transfer['participants']) == 0:
                del active_transfers[room_id]
                if room_id in room_creation_times:
                    del room_creation_times[room_id]

@socketio.on('create_room')
def handle_create_room(data):
    client_ip = get_client_ip()
    
#    if not check_rate_limit(client_ip):
#        emit('error', {'message': 'Trop de tentatives. Patientez.'})
#        return
    
    try:
        room_id = secrets.token_urlsafe(ROOM_ID_LENGTH)
        
        active_transfers[room_id] = {
            'participants': [request.sid],
            'sender': request.sid,
            'receiver': None,
            'created_at': time.time(),
            'creator_ip': client_ip,
            'chunk_count': 0
        }
        
        room_creation_times[room_id] = time.time()
        join_room(room_id)
        
        emit('room_created', {'room_id': room_id})
        logger.info(f'Room created: {room_id}')
        
    except Exception as e:
        logger.error(f'Create room error: {e}')
        emit('error', {'message': 'Erreur serveur'})

@socketio.on('join_room')
def handle_join_room(data):
    try:
        room_id = sanitize_string(data.get('room_id')) if isinstance(data, dict) else None
        client_ip = get_client_ip()
        
        if not room_id or not check_rate_limit(client_ip):
            emit('error', {'message': 'Requête invalide ou trop fréquente'})
            return
            
        if room_id in revoked_rooms:
            emit('error', {'message': 'Session terminée'})
            return

        if room_id not in active_transfers:
            emit('error', {'message': 'Code invalide ou expiré'})
            return
            
        transfer_data = active_transfers[room_id]
        
        # Sécurité : Limite stricte à 2 personnes (P2P style)
        if len(transfer_data['participants']) >= 2:
            emit('error', {'message': 'Session complète'})
            return
            
        # Enregistrement du récepteur
        transfer_data['participants'].append(request.sid)
        transfer_data['receiver'] = request.sid
        
        join_room(room_id)
        
        # Signalling P2P : On prévient l'expéditeur qu'il peut commencer
        emit('room_joined', {}) # Au récepteur
        emit('peer_connected', {}, to=transfer_data['sender']) # A l'expéditeur
        
        logger.info(f'Match established in room: {room_id}')
        
    except Exception as e:
        logger.error(f'Join error: {e}')
        emit('error', {'message': 'Erreur de connexion'})

@socketio.on('file_info')
def handle_file_info(data):
    # Relais des métadonnées (nom, taille, type) chiffrées
    try:
        room_id = sanitize_string(data.get('room_id'))
        encrypted_metadata = data.get('encrypted_metadata') # Peut être long, pas de sanitize
        
        if not room_id or room_id not in active_transfers:
            return
            
        transfer_data = active_transfers[room_id]
        
        # AUTORISATION STRICTE : Seul le sender déclaré peut envoyer des infos
        if request.sid != transfer_data.get('sender'):
            logger.warning(f'Unauthorized file_info from {request.sid}')
            return
            
        # Limite de taille pour éviter le bourrage mémoire
        if len(str(encrypted_metadata)) > 20000: 
            emit('error', {'message': 'Métadonnées trop lourdes'})
            return

        receiver = transfer_data.get('receiver')
        if receiver:
            emit('file_info', {'encrypted_metadata': encrypted_metadata}, to=receiver)
            
    except Exception as e:
        logger.error(f'File info error: {e}')

@socketio.on('file_chunk')
def handle_file_chunk(data):
    """
    Cœur du transfert.
    DESIGN DE SÉCURITÉ : Zéro stockage. Relais immédiat.
    """
    try:
        room_id = data.get('room_id') # Pas de sanitize ici pour perf, check dict direct
        if not room_id or room_id not in active_transfers:
            return

        transfer_data = active_transfers[room_id]
        
        # 1. Autorisation
        if request.sid != transfer_data.get('sender'):
            return # Silence pour les attaquants

        # 2. Validation de la charge utile (Payload)
        chunk = data.get('chunk')
        # Accepte bytes (binaire) ou str (base64)
        if not isinstance(chunk, (bytes, str)):
            return 
        
        # Protection DoS Mémoire
        if len(chunk) > MAX_CHUNK_SIZE:
            emit('error', {'message': 'Paquet trop volumineux'}, to=request.sid)
            return

        # 3. Limite globale
        if transfer_data['chunk_count'] > MAX_CHUNKS_PER_TRANSFER:
            emit('error', {'message': 'Limite de transfert atteinte'}, to=request.sid)
            return

        transfer_data['chunk_count'] += 1
        
        # 4. RELAIS IMMÉDIAT (Pass-through)
        # On ne stocke rien. On envoie directement au récepteur.
        receiver = transfer_data.get('receiver')
        if receiver:
            # On nettoie data pour ne garder que l'essentiel
            payload = {
                'chunk': chunk,
                'sequence': data.get('sequence'),
                'index': data.get('index'),
                'is_last': data.get('is_last', False),
                'chunk_hash': data.get('chunk_hash')
            }
            emit('file_chunk', payload, to=receiver)

    except Exception as e:
        logger.error(f'Chunk error: {e}')
        emit('request_chunk_retry', {'chunk_index': data.get('index')}, to=request.sid)

@socketio.on('transfer_complete')
def handle_transfer_complete(data):
    try:
        room_id = sanitize_string(data.get('room_id'))
        file_hash = sanitize_string(data.get('file_hash'))
        
        if not room_id or room_id not in active_transfers:
            return
            
        transfer_data = active_transfers[room_id]
        
        # Relais final
        for participant in transfer_data['participants']:
            emit('transfer_complete', {'file_hash': file_hash}, to=participant)
            
        # NETTOYAGE IMMÉDIAT (Security hygiene)
        # Une fois fini, la salle n'existe plus.
        logger.info(f'Transfer success. Destroying room: {room_id}')
        del active_transfers[room_id]
        if room_id in room_creation_times:
            del room_creation_times[room_id]
            
    except Exception as e:
        logger.error(f'Completion error: {e}')

@socketio.on('transfer_progress')
def handle_progress(data):
    # Simple relais pour la barre de progression
    room_id = data.get('room_id')
    if room_id in active_transfers:
        transfer_data = active_transfers[room_id]
        sender = transfer_data.get('sender')
        # Seul le receiver envoie la progression, on la renvoie au sender
        if request.sid != sender: 
            emit('transfer_progress', {'progress': data.get('progress')}, to=sender)

@socketio.on('revoke_room')
def handle_revoke(data):
    room_id = sanitize_string(data.get('room_id'))
    if room_id in active_transfers:
        transfer_data = active_transfers[room_id]
        if request.sid == transfer_data.get('sender'):
            revoked_rooms.add(room_id)
            receiver = transfer_data.get('receiver')
            if receiver:
                emit('room_revoked', {}, to=receiver)
            del active_transfers[room_id]

@socketio.on('request_chunk_retry')
def handle_retry(data):
    # Relais de demande de renvoi de paquet
    room_id = data.get('room_id')
    if room_id in active_transfers:
        transfer_data = active_transfers[room_id]
        # Seul le receiver peut demander un retry
        if request.sid == transfer_data.get('receiver'):
            emit('request_chunk_retry', {'chunk_index': data.get('chunk_index')}, to=transfer_data['sender'])

if __name__ == '__main__':
    # Configuration DEV sécurisée pour accepter Flask-SocketIO
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)