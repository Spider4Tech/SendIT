const socket = io();

// --- ÉTAT GLOBAL SÉCURISÉ ---
let appState = {
    currentScreen: 'home',
    selectedFile: null,
    roomId: null,
    cryptoKey: null, // Uint8Array
    receivedChunks: [],
    totalChunks: 0,
    fileInfo: null,
    chunkSequence: 0,
    expectedSequence: 0,
    fileHashInput: [], // Pour calcul hash progressif
    finalFileHash: null // Hash reçu de l'expéditeur
};

// Buffer pour les chunks arrivés dans le désordre
let outOfOrderBuffer = new Map();
let failedChunks = new Set();
let retryAttempts = {};

// --- CONSTANTES DE SÉCURITÉ ---
const CHUNK_SIZE = 64 * 1024; // 64KB
const PADDED_CHUNK_SIZE = CHUNK_SIZE + 4; // +4 bytes pour la taille
const MAX_RETRIES = 3;
const BROWSER_MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB (Limite hard browser pour éviter crash mémoire)

// --- UTILITAIRES SÉCURITÉ (CRYPTO & SANITIZATION) ---

/**
 * Empêche les attaques XSS via les noms de fichiers
 */
function escapeHtml(text) {
    if (!text) return text;
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function generateEncryptionKey() {
    return nacl.randomBytes(nacl.secretbox.keyLength);
}

/**
 * Export clé pour l'URL (Base64URL Safe idéalement, ici Base64 standard pour compatibilité)
 */
function exportKey(key) {
    return arrayBufferToBase64(key);
}

function importKey(keyBase64) {
    const buffer = base64ToArrayBuffer(keyBase64);
    if (buffer.byteLength !== nacl.secretbox.keyLength) {
        throw new Error("Longueur de clé invalide");
    }
    return new Uint8Array(buffer);
}

/**
 * Chiffrement optimisé pour le binaire (Zéro Base64)
 * Retourne: Uint8Array (Nonce + Ciphertext)
 */
function encryptDataBinary(data, key) {
    let dataToEncrypt;
    if (typeof data === 'string') {
        dataToEncrypt = new TextEncoder().encode(data);
    } else if (data instanceof ArrayBuffer) {
        dataToEncrypt = new Uint8Array(data);
    } else {
        dataToEncrypt = data;
    }
    
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const encrypted = nacl.secretbox(dataToEncrypt, nonce, key);
    
    // Concaténation performante
    const combined = new Uint8Array(nonce.length + encrypted.length);
    combined.set(nonce, 0);
    combined.set(encrypted, nonce.length);
    
    return combined; // Retourne du binaire pur
}

/**
 * Déchiffrement optimisé pour le binaire
 */
function decryptDataBinary(data, key) {
    // data peut être ArrayBuffer ou Uint8Array venant de Socket.io
    const combined = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    
    const nonceLength = nacl.secretbox.nonceLength;
    if (combined.length < nonceLength) throw new Error("Données trop courtes");

    const nonce = combined.slice(0, nonceLength);
    const ciphertext = combined.slice(nonceLength);
    
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    
    if (!decrypted) {
        throw new Error('Échec déchiffrement - Intégrité compromise');
    }
    
    return decrypted;
}

// Helpers Base64 (Uniquement pour l'échange de clé initial et JSON)
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Hashing
async function sha256(data) {
    const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return arrayBufferToBase64(hashBuffer);
}

async function computeChunkHash(chunkData) {
    return await sha256(chunkData);
}

// Padding (Obfuscation taille exacte)
function padChunk(chunk) {
    if (chunk.byteLength >= PADDED_CHUNK_SIZE) return chunk;
    
    const padded = new Uint8Array(PADDED_CHUNK_SIZE);
    padded.set(new Uint8Array(chunk), 0);
    // Remplissage avec données aléatoires (pas de zéros) pour sécurité crypto
    const padding = nacl.randomBytes(PADDED_CHUNK_SIZE - chunk.byteLength);
    padded.set(padding, chunk.byteLength);
    return padded.buffer;
}

function removePadding(paddedChunk, originalSize) {
    return paddedChunk.slice(0, originalSize);
}

// --- UI / UX APPLE STYLE ---

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toastEl = document.createElement('div');
    toastEl.className = `toast ${type}`;
    
    const icons = { success: '✓', error: '✕', warning: '!', info: 'ℹ' };

    // Utilisation de textContent pour éviter XSS dans le message
    toastEl.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <div class="toast-content">
            <div class="toast-title"></div>
        </div>
    `;
    toastEl.querySelector('.toast-title').textContent = message; // Insertion sécurisée
    
    container.appendChild(toastEl);
    
    setTimeout(() => {
        toastEl.classList.add('exit');
        setTimeout(() => toastEl.remove(), 300);
    }, 4000);
}

function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
        setTimeout(() => {
            if(!screen.classList.contains('active')) screen.style.display = 'none';
        }, 300); 
    });

    const targetScreen = document.getElementById(screenId + '-screen');
    targetScreen.style.display = 'block';
    void targetScreen.offsetWidth; // Force Reflow
    targetScreen.classList.add('active');
    appState.currentScreen = screenId;
}

function showHomeScreen() { resetState(); showScreen('home'); }
function showSendScreen() { showScreen('send'); }
function showReceiveScreen() { showScreen('receive'); }

function resetState() {
    // Nettoyage profond
    appState = {
        currentScreen: 'home',
        selectedFile: null,
        roomId: null,
        cryptoKey: null,
        receivedChunks: [],
        totalChunks: 0,
        fileInfo: null,
        chunkSequence: 0,
        expectedSequence: 0,
        fileHashInput: [],
        finalFileHash: null
    };
    outOfOrderBuffer.clear();
    failedChunks.clear();
    retryAttempts = {};
    
    // UI Reset
    document.getElementById('file-info').innerHTML = '';
    document.getElementById('connection-code-section').style.display = 'none';
    document.getElementById('send-progress').style.display = 'none';
    document.getElementById('receive-progress').style.display = 'none';
    const codeInput = document.getElementById('room-code-input');
    if(codeInput) codeInput.value = '';
    document.getElementById('receive-file-info').innerHTML = '';
}

function handleFileSelect(event) {
    try {
        const file = event.target.files[0];
        if (!file) return;

        if (file.size > BROWSER_MAX_FILE_SIZE) {
            showToast(`Fichier trop volumineux (>1GB). Limite navigateur.`, 'error');
            event.target.value = ''; // Reset input
            return;
        }

        appState.selectedFile = file;
        const sizeInMB = (file.size / (1024 * 1024)).toFixed(2);
        
        // Affichage sécurisé (escapeHtml)
        document.getElementById('file-info').innerHTML = `
            <div style="font-weight: 600; font-size: 15px; margin-bottom: 4px;">${escapeHtml(file.name)}</div>
            <div style="color: var(--text-secondary); font-size: 13px;">${sizeInMB} MB • ${escapeHtml(file.type) || 'Fichier'}</div>
        `;
        
        console.log('Génération clé de chiffrement...');
        appState.cryptoKey = generateEncryptionKey();
        socket.emit('create_room', {});

    } catch (error) {
        console.error('Error:', error);
        showToast('Erreur de sélection', 'error');
    }
}

function copyCode() {
    const code = document.getElementById('connection-code').textContent;
    navigator.clipboard.writeText(code)
        .then(() => showToast('Code copié', 'success'))
        .catch(() => showToast('Erreur de copie', 'error'));
}

// --- LOGIQUE TRANSFERT ---

function joinRoom() {
    const codeInput = document.getElementById('room-code-input');
    const code = codeInput.value.trim();
    
    if (!code) {
        showToast('Veuillez entrer un code', 'warning');
        return;
    }
    
    const parts = code.split('::');
    if (parts.length !== 2) {
        showToast('Format de code invalide', 'error');
        return;
    }
    
    appState.roomId = parts[0];
    try {
        appState.cryptoKey = importKey(parts[1]);
        socket.emit('join_room', { room_id: appState.roomId });
    } catch (e) {
        showToast('Clé de chiffrement invalide', 'error');
    }
}

async function sendFile() {
    if (!appState.selectedFile || !appState.roomId || !appState.cryptoKey) return;
    
    document.getElementById('waiting-status').style.display = 'none';
    document.getElementById('send-progress').style.display = 'block';
    
    // Métadonnées chiffrées (JSON -> String -> Binary -> Encrypt)
    const metadata = JSON.stringify({
        name: appState.selectedFile.name,
        size: appState.selectedFile.size,
        type: appState.selectedFile.type,
        timestamp: Date.now()
    });
    
    // On utilise base64 pour les métadonnées car c'est du JSON transporté
    const encryptedMetadata = arrayBufferToBase64(encryptDataBinary(metadata, appState.cryptoKey));
    
    socket.emit('file_info', {
        room_id: appState.roomId,
        encrypted_metadata: encryptedMetadata
    });
    
    appState.totalChunks = Math.ceil(appState.selectedFile.size / CHUNK_SIZE);
    let sentChunks = 0;
    appState.chunkSequence = 0;
    let fileHashAccumulator = [];
    
    const reader = new FileReader();
    let offset = 0;
    
    const readNextChunk = () => {
        const slice = appState.selectedFile.slice(offset, offset + CHUNK_SIZE);
        reader.readAsArrayBuffer(slice);
    };
    
    reader.onload = async (e) => {
        try {
            const chunk = e.target.result; // ArrayBuffer
            const chunkSize = chunk.byteLength;
            
            // Préparation données (Taille + Data)
            const sizeHeader = new Uint32Array([chunkSize]);
            const chunkWithSize = new Uint8Array(4 + chunk.byteLength);
            chunkWithSize.set(new Uint8Array(sizeHeader.buffer), 0);
            chunkWithSize.set(new Uint8Array(chunk), 4);
            
            // Padding & Hashing
            const paddedChunk = padChunk(chunkWithSize.buffer);
            const chunkHash = await computeChunkHash(paddedChunk);
            
            // Pour le hash final global
            fileHashAccumulator.push(new Uint8Array(chunk));
            
            // Chiffrement BINAIRE pur (pas de base64 ici !)
            const encryptedChunk = encryptDataBinary(paddedChunk, appState.cryptoKey);
            
            socket.emit('file_chunk', {
                room_id: appState.roomId,
                chunk: encryptedChunk, // Envoi buffer direct
                sequence: appState.chunkSequence,
                index: sentChunks,
                is_last: sentChunks === appState.totalChunks - 1,
                chunk_hash: chunkHash
            });
            
            appState.chunkSequence++;
            sentChunks++;
            offset += CHUNK_SIZE;
            
            updateSendProgress((sentChunks / appState.totalChunks) * 100);
            
            if (offset < appState.selectedFile.size) {
                // Petit délai pour laisser respirer l'Event Loop
                if (sentChunks % 50 === 0) await new Promise(r => setTimeout(r, 0));
                readNextChunk();
            } else {
                // Calcul Hash Final
                const combinedData = new Uint8Array(fileHashAccumulator.reduce((acc, arr) => acc + arr.length, 0));
                let pos = 0;
                for (let arr of fileHashAccumulator) {
                    combinedData.set(arr, pos);
                    pos += arr.length;
                }
                const fileHash = await sha256(combinedData);
                
                socket.emit('transfer_complete', { 
                    room_id: appState.roomId, 
                    file_hash: fileHash 
                });
                
                setTimeout(() => showScreen('complete'), 500);
            }
        } catch (error) {
            console.error('Chunk Error:', error);
            showToast('Erreur lecture fichier', 'error');
        }
    };
    
    reader.onerror = () => showToast('Erreur lecture fichier', 'error');
    readNextChunk();
}

function updateSendProgress(progress) {
    document.getElementById('send-progress-fill').style.width = progress + '%';
    document.getElementById('send-progress-text').textContent = Math.round(progress) + '%';
}

function updateReceiveProgress(progress) {
    document.getElementById('receive-progress-fill').style.width = progress + '%';
    document.getElementById('receive-progress-text').textContent = Math.round(progress) + '%';
    
    // Feedback optionnel
    if (progress % 5 < 1) socket.emit('transfer_progress', { room_id: appState.roomId, progress: progress });
}

// --- SOCKET EVENTS ---

// Dans app.js

socket.on('room_created', (data) => {
    // 🚩 VÉRIFICATION CRITIQUE 🚩
    console.log('--- ROOM CREATED EVENT RECEIVED ---', data); 
    // Si ce log n'apparaît pas, l'événement est perdu entre le serveur et le client.
    
    try {
        appState.roomId = data.room_id;
        const keyBase64 = exportKey(appState.cryptoKey); 
        const fullCode = `${appState.roomId}::${keyBase64}`;
        
        document.getElementById('connection-code').textContent = fullCode;
        document.getElementById('connection-code-section').style.display = 'block';
        showToast('Salle prête. Code généré.', 'success');
        
    } catch (e) {
        // --- CATCH LES ERREURS DANS CE BLOC UNIQUEMENT ---
        console.error("Erreur critique d'affichage du code/clé:", e);
        showToast("Erreur d'initialisation de session.", 'error');
    }
});

socket.on('room_joined', () => {
    document.getElementById('receive-progress').style.display = 'block';
    showToast('Connexion établie. Attente...', 'info');
});

socket.on('peer_connected', () => {
    sendFile();
    showToast('Destinataire prêt. Envoi...', 'info');
});

socket.on('file_info', (data) => {
    try {
        // 1. Déchiffrement
        const decryptedBytes = decryptDataBinary(base64ToArrayBuffer(data.encrypted_metadata), appState.cryptoKey);
        const metadataStr = new TextDecoder().decode(decryptedBytes);
        appState.fileInfo = JSON.parse(metadataStr);
        
        // 2. Affichage sécurisé
        const sizeInMB = (appState.fileInfo.size / (1024 * 1024)).toFixed(2);
        document.getElementById('receive-file-info').innerHTML = `
            <div style="font-weight:600; margin-bottom:4px;">${escapeHtml(appState.fileInfo.name)}</div>
            <div style="color:var(--text-secondary); font-size:13px;">${sizeInMB} MB</div>
        `;
        
        // 3. Préparation
        appState.totalChunks = Math.ceil(appState.fileInfo.size / CHUNK_SIZE);
        appState.receivedChunks = new Array(appState.totalChunks);
        appState.expectedSequence = 0;
        
    } catch (e) {
        console.error('Metadata Error:', e);
        showToast('Erreur intégrité métadonnées', 'error');
        socket.emit('revoke_room', { room_id: appState.roomId });
    }
});

async function processChunk(data) {
    // data.chunk est un ArrayBuffer/Uint8Array brut ici (pas de base64)
    const decryptedPaddedChunk = decryptDataBinary(data.chunk, appState.cryptoKey);
    
    // Vérification Hash du Chunk (Intégrité niveau paquet)
    if (data.chunk_hash) {
        const computedHash = await computeChunkHash(decryptedPaddedChunk);
        if (computedHash !== data.chunk_hash) {
            failedChunks.add(data.index);
            showToast('Chunk corrompu détecté', 'warning');
            socket.emit('request_chunk_retry', { room_id: appState.roomId, chunk_index: data.index });
            return false;
        }
    }
    
    // Extraction taille réelle
    const sizeHeader = new Uint32Array(decryptedPaddedChunk.slice(0, 4).buffer)[0];
    const chunkWithSize = decryptedPaddedChunk.slice(4);
    const decryptedChunk = removePadding(chunkWithSize, sizeHeader);
    
    appState.receivedChunks[data.index] = decryptedChunk;
    failedChunks.delete(data.index);
    return true;
}

async function tryProcessBufferedChunks() {
    let processed = true;
    while (processed && outOfOrderBuffer.has(appState.expectedSequence)) {
        processed = false;
        const bufferedData = outOfOrderBuffer.get(appState.expectedSequence);
        outOfOrderBuffer.delete(appState.expectedSequence);
        
        try {
            if (await processChunk(bufferedData)) {
                appState.expectedSequence++;
                processed = true;
            }
        } catch (e) {
            failedChunks.add(bufferedData.index);
            socket.emit('request_chunk_retry', { room_id: appState.roomId, chunk_index: bufferedData.index });
        }
    }
}

function isAllChunksReceived() {
    if (appState.totalChunks === 0) return false;
    let count = 0;
    for (let i = 0; i < appState.totalChunks; i++) {
        if (appState.receivedChunks[i] !== undefined) count++;
    }
    return count === appState.totalChunks;
}

socket.on('file_chunk', async (data) => {
    try {
        if (data.sequence < appState.expectedSequence) return;
        
        if (data.sequence > appState.expectedSequence) {
            outOfOrderBuffer.set(data.sequence, data);
            return;
        }
        
        if (await processChunk(data)) {
            appState.expectedSequence++;
            await tryProcessBufferedChunks();
            
            // Calcul progression exact
            let receivedCount = 0;
            for(let i=0; i<appState.receivedChunks.length; i++) {
                if(appState.receivedChunks[i]) receivedCount++;
            }
            
            updateReceiveProgress((receivedCount / appState.totalChunks) * 100);
            
            // Fin du transfert ?
            if (isAllChunksReceived() && appState.finalFileHash) {
                finalizeDownload();
            }
        }
    } catch (e) {
        console.error('Chunk Process Fail:', e);
        socket.emit('request_chunk_retry', { room_id: appState.roomId, chunk_index: data.index });
    }
});

socket.on('transfer_complete', (data) => {
    if (data && data.file_hash) {
        appState.finalFileHash = data.file_hash;
        // Si on a déjà tous les chunks, on lance la finalisation
        if (isAllChunksReceived()) finalizeDownload();
    }
});

async function finalizeDownload() {
    // 1. Reconstruction Blob
    const completeBlob = new Blob(appState.receivedChunks, { type: appState.fileInfo.type });
    
    // 2. Vérification Hash FINAL (Intégrité Fichier Complet)
    // C'est l'étape critique "Intransigeante"
    const buffer = await completeBlob.arrayBuffer();
    const computedFinalHash = await sha256(buffer);
    
    if (computedFinalHash !== appState.finalFileHash) {
        showToast('ERREUR FATALE: Hash fichier invalide ! Destruction.', 'error');
        resetState(); // On détruit tout, pas de téléchargement
        return;
    }
    
    // 3. Téléchargement si valide
    const url = URL.createObjectURL(completeBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = appState.fileInfo.name; // Nom déjà sanitize par le navigateur au download
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Vérifié & Déchiffré avec succès', 'success');
    setTimeout(() => showScreen('complete'), 1000);
}

socket.on('transfer_progress', (data) => {
    if (data?.progress) updateSendProgress(data.progress);
});

socket.on('error', (data) => showToast(data.message || 'Erreur', 'error'));

socket.on('room_revoked', () => {
    showToast('Session terminée', 'warning');
    setTimeout(showHomeScreen, 1500);
});

socket.on('disconnect', () => showToast('Connexion perdue', 'warning'));

console.log('SendIT Secure Client v2.0 Loaded');