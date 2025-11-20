const socket = io();

let currentScreen = 'home';
let selectedFile = null;
let roomId = null;
let cryptoKey = null;
let receivedChunks = [];
let totalChunks = 0;
let fileInfo = null;
let chunkSequence = 0;
let expectedSequence = 0;

const CHUNK_SIZE = 64 * 1024;
const PADDED_CHUNK_SIZE = CHUNK_SIZE + 4;

function showToast(message, type = 'info', title = null) {
    const container = document.getElementById('toast-container');
    
    const toastEl = document.createElement('div');
    toastEl.className = `toast ${type}`;
    
    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };
    
    const titles = {
        success: 'Succès',
        error: 'Erreur',
        warning: 'Attention',
        info: 'Information'
    };
    
    toastEl.innerHTML = `
        <div class="toast-icon">${icons[type] || icons.info}</div>
        <div class="toast-content">
            <div class="toast-title">${title || titles[type]}</div>
            <div class="toast-message">${message}</div>
        </div>
    `;
    
    container.appendChild(toastEl);
    
    setTimeout(() => {
        toastEl.classList.add('exit');
        setTimeout(() => toastEl.remove(), 300);
    }, 4000);
}

function generateEncryptionKey() {
    return nacl.randomBytes(nacl.secretbox.keyLength);
}

function exportKey(key) {
    const keyBuffer = key.buffer || key;
    return arrayBufferToBase64(keyBuffer);
}

function importKey(keyBase64) {
    const buffer = base64ToArrayBuffer(keyBase64);
    return new Uint8Array(buffer);
}

function encryptData(data, key) {
    let dataToEncrypt;
    if (typeof data === 'string') {
        dataToEncrypt = new TextEncoder().encode(data);
    } else if (data instanceof ArrayBuffer) {
        dataToEncrypt = new Uint8Array(data);
    } else {
        dataToEncrypt = data;
    }
    
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const keyArray = new Uint8Array(key);
    const encrypted = nacl.secretbox(dataToEncrypt, nonce, keyArray);
    
    const combined = new Uint8Array(nonce.length + encrypted.length);
    combined.set(nonce, 0);
    combined.set(encrypted, nonce.length);
    
    return arrayBufferToBase64(combined.buffer);
}

function decryptData(encryptedBase64, key) {
    const combined = new Uint8Array(base64ToArrayBuffer(encryptedBase64));
    const nonceLength = nacl.secretbox.nonceLength;
    const nonce = combined.slice(0, nonceLength);
    const encrypted = combined.slice(nonceLength);
    
    const keyArray = new Uint8Array(key);
    const decrypted = nacl.secretbox.open(encrypted, nonce, keyArray);
    
    if (!decrypted) {
        throw new Error('Decryption failed - data may be corrupted or modified');
    }
    
    return decrypted;
}



function padChunk(chunk) {
    if (chunk.byteLength >= PADDED_CHUNK_SIZE) {
        return chunk;
    }
    
    const padded = new Uint8Array(PADDED_CHUNK_SIZE);
    padded.set(new Uint8Array(chunk), 0);
    
    const padding = crypto.getRandomValues(new Uint8Array(PADDED_CHUNK_SIZE - chunk.byteLength));
    padded.set(padding, chunk.byteLength);
    
    return padded.buffer;
}

function removePadding(paddedChunk, originalSize) {
    return paddedChunk.slice(0, originalSize);
}

function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId + '-screen').classList.add('active');
    currentScreen = screenId;
}

function showHomeScreen() {
    resetState();
    showScreen('home');
}

function showSendScreen() {
    showScreen('send');
}

function showReceiveScreen() {
    showScreen('receive');
}

function resetState() {
    selectedFile = null;
    roomId = null;
    cryptoKey = null;
    receivedChunks = [];
    totalChunks = 0;
    fileInfo = null;
    chunkSequence = 0;
    expectedSequence = 0;
    
    document.getElementById('file-info').innerHTML = '';
    document.getElementById('connection-code-section').style.display = 'none';
    document.getElementById('send-progress').style.display = 'none';
    document.getElementById('receive-progress').style.display = 'none';
    document.getElementById('room-code-input').value = '';
}

function handleFileSelect(event) {
    try {
        selectedFile = event.target.files[0];
        if (selectedFile) {
            const fileInfoDiv = document.getElementById('file-info');
            const sizeInMB = (selectedFile.size / (1024 * 1024)).toFixed(2);
            fileInfoDiv.innerHTML = `
                <strong>${selectedFile.name}</strong><br>
                Taille: ${sizeInMB} MB<br>
                Type: ${selectedFile.type || 'inconnu'}
            `;
            
            console.log('Generating encryption key...');
            cryptoKey = generateEncryptionKey();
            console.log('Key generated, creating room...');
            
            socket.emit('create_room', {});
        }
    } catch (error) {
        console.error('Error in handleFileSelect:', error);
        showToast(error.message, 'error', 'Erreur de sélection');
    }
}

function copyCode() {
    const code = document.getElementById('connection-code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        showToast('Code copié dans le presse-papier', 'success', 'Copié');
    }).catch(() => {
        showToast('Impossible de copier le code', 'error', 'Erreur');
    });
}

function joinRoom() {
    const code = document.getElementById('room-code-input').value.trim();
    if (!code) {
        showToast('Veuillez entrer un code de connexion', 'warning');
        return;
    }
    
    const parts = code.split('::');
    if (parts.length !== 2) {
        showToast('Code de connexion invalide', 'error');
        return;
    }
    
    roomId = parts[0];
    const keyBase64 = parts[1];
    
    try {
        cryptoKey = importKey(keyBase64);
        socket.emit('join_room', { room_id: roomId });
    } catch (e) {
        showToast('Code de connexion invalide', 'error');
        console.error('Key import error:', e);
    }
}

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

async function sendFile() {
    if (!selectedFile || !roomId || !cryptoKey) return;
    
    document.getElementById('waiting-status').style.display = 'none';
    document.getElementById('send-progress').style.display = 'block';
    
    const encryptedMetadata = encryptData(JSON.stringify({
        name: selectedFile.name,
        size: selectedFile.size,
        type: selectedFile.type,
        timestamp: Date.now()
    }), cryptoKey);
    
    socket.emit('file_info', {
        room_id: roomId,
        encrypted_metadata: encryptedMetadata
    });
    
    totalChunks = Math.ceil(selectedFile.size / CHUNK_SIZE);
    let sentChunks = 0;
    chunkSequence = 0;
    
    const reader = new FileReader();
    let offset = 0;
    
    const readNextChunk = () => {
        const slice = selectedFile.slice(offset, offset + CHUNK_SIZE);
        reader.readAsArrayBuffer(slice);
    };
    
    reader.onload = (e) => {
        const chunk = e.target.result;
        const chunkSize = chunk.byteLength;
        
        const sizeHeader = new Uint32Array([chunkSize]);
        const chunkWithSize = new Uint8Array(4 + chunk.byteLength);
        chunkWithSize.set(new Uint8Array(sizeHeader.buffer), 0);
        chunkWithSize.set(new Uint8Array(chunk), 4);
        
        const paddedChunk = padChunk(chunkWithSize.buffer);
        
        const encryptedChunk = encryptData(paddedChunk, cryptoKey);
        
        socket.emit('file_chunk', {
            room_id: roomId,
            chunk: encryptedChunk,
            sequence: chunkSequence,
            index: sentChunks,
            is_last: sentChunks === totalChunks - 1
        });
        
        chunkSequence++;
        sentChunks++;
        offset += CHUNK_SIZE;
        
        const progress = (sentChunks / totalChunks) * 100;
        updateSendProgress(progress);
        
        if (offset < selectedFile.size) {
            readNextChunk();
        } else {
            socket.emit('transfer_complete', { 
                room_id: roomId
            });
            setTimeout(() => showScreen('complete'), 500);
        }
    };
    
    readNextChunk();
}

function updateSendProgress(progress) {
    const progressFill = document.getElementById('send-progress-fill');
    const progressText = document.getElementById('send-progress-text');
    progressFill.style.width = progress + '%';
    progressText.textContent = Math.round(progress) + '%';
}

function updateReceiveProgress(progress) {
    const progressFill = document.getElementById('receive-progress-fill');
    const progressText = document.getElementById('receive-progress-text');
    progressFill.style.width = progress + '%';
    progressText.textContent = Math.round(progress) + '%';
    
    socket.emit('transfer_progress', {
        room_id: roomId,
        progress: progress
    });
}

socket.on('room_created', (data) => {
    try {
        console.log('Room created:', data);
        roomId = data.room_id;
        const keyBase64 = exportKey(cryptoKey);
        
        const fullCode = `${roomId}::${keyBase64}`;
        console.log('Generated code:', fullCode);
        document.getElementById('connection-code').textContent = fullCode;
        document.getElementById('connection-code-section').style.display = 'block';
        showToast('Salle créée. Partagez le code avec votre destinataire', 'success', 'Prêt');
    } catch (error) {
        console.error('Error in room_created:', error);
        showToast(error.message, 'error', 'Erreur de création');
    }
});

socket.on('room_joined', (data) => {
    document.getElementById('receive-progress').style.display = 'block';
    showToast('Connecté au partage. Préparation de la réception...', 'info', 'Connecté');
});

socket.on('peer_connected', () => {
    sendFile();
});

socket.on('file_info', (data) => {
    try {
        console.log('Received file_info, encrypted_metadata length:', data.encrypted_metadata.length);
        console.log('Crypto key:', typeof cryptoKey, 'length:', cryptoKey.byteLength || cryptoKey.length);
        if (cryptoKey.byteLength !== 32 && cryptoKey.length !== 32) {
            console.error('KEY SIZE MISMATCH! Expected 32, got:', cryptoKey.byteLength || cryptoKey.length);
        }
        
        const decryptedMetadata = decryptData(data.encrypted_metadata, cryptoKey);
        console.log('Decrypted metadata type:', decryptedMetadata.constructor.name, 'length:', decryptedMetadata.length);
        
        const metadataStr = new TextDecoder().decode(decryptedMetadata);
        console.log('Metadata string first 50 chars:', metadataStr.substring(0, 50));
        
        fileInfo = JSON.parse(metadataStr);
        
        const sizeInMB = (fileInfo.size / (1024 * 1024)).toFixed(2);
        document.getElementById('receive-file-info').innerHTML = `
            <strong>${fileInfo.name}</strong><br>
            Taille: ${sizeInMB} MB
        `;
        
        totalChunks = Math.ceil(fileInfo.size / CHUNK_SIZE);
        receivedChunks = new Array(totalChunks);
        expectedSequence = 0;
        console.log('File info processed successfully');
    } catch (e) {
        console.error('Metadata decryption failed:', e);
        console.error('Stack:', e.stack);
        showToast('Impossible de déchiffrer les métadonnées du fichier', 'error', 'Erreur de déchiffrement');
    }
});

socket.on('file_chunk', (data) => {
    try {
        if (data.sequence > expectedSequence) {
            console.error('Sequence ahead! Expected:', expectedSequence, 'Got:', data.sequence);
            return;
        }
        
        if (data.sequence < expectedSequence) {
            console.warn('Duplicate chunk received, ignoring');
            return;
        }
        
        const decryptedPaddedChunk = decryptData(data.chunk, cryptoKey);
        
        const sizeHeader = new Uint32Array(decryptedPaddedChunk.slice(0, 4))[0];
        const chunkWithSize = decryptedPaddedChunk.slice(4);
        const decryptedChunk = removePadding(chunkWithSize, sizeHeader);
        
        receivedChunks[data.index] = decryptedChunk;
        expectedSequence++;
        
        const receivedCount = receivedChunks.filter(c => c !== undefined).length;
        const progress = (receivedCount / totalChunks) * 100;
        updateReceiveProgress(progress);
        
        if (data.is_last) {
            const completeFile = new Blob(receivedChunks, { type: fileInfo.type });
            const url = URL.createObjectURL(completeFile);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = fileInfo.name;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    } catch (e) {
        console.error('Chunk processing failed:', e);
        showToast('Erreur lors de la réception d\'un fichier. Possible modification détectée.', 'error', 'Erreur de déchiffrement');
    }
});

socket.on('transfer_complete', () => {
    setTimeout(() => showScreen('complete'), 500);
});

socket.on('transfer_progress', (data) => {
    updateSendProgress(data.progress);
});

socket.on('error', (data) => {
    showToast(data.message, 'error', 'Erreur de transfert');
});

socket.on('connect', () => {
    console.log('✓ Connected to server');
    showToast('Connecté au serveur de transfert', 'success', 'Connexion établie');
});

socket.on('disconnect', () => {
    console.log('✗ Disconnected from server');
    showToast('Connecté au serveur', 'warning', 'Connexion perdue');
});

console.log('✓ App loaded with TweetNaCl (XSalsa20-Poly1305)');
