# SendIT - Transfert de Fichiers Ultra Sécurisé

## Vue d'ensemble
SendIT est une application web de transfert de fichiers ultra sécurisée avec chiffrement de bout en bout conçue pour résister à des adversaires étatiques. L'application permet de transférer des fichiers entre deux ordinateurs de manière fiable et confidentielle. Le serveur agit uniquement comme relais de signalisation - **il ne peut jamais déchiffrer les données**.

## Fonctionnalités de sécurité (niveau adversaire étatique)

### Chiffrement et authentification
- ✅ **Chiffrement de bout en bout** avec AES-GCM 256 bits
- ✅ **Métadonnées chiffrées** - nom, taille, type du fichier jamais en clair
- ✅ **HMAC-SHA256** pour authentification de chaque chunk
- ✅ **Protection anti-rejeu** avec séquençage des chunks
- ✅ **Padding cryptographique** pour masquer la taille réelle
- ✅ **Serveur aveugle** - ne voit que du ciphertext
- ✅ **Clés locales** - génération côté client uniquement

### Protection du réseau
- ✅ **Headers de sécurité HTTP** (CSP, HSTS, X-Frame-Options, etc.)
- ✅ **Rate limiting** - max 10 tentatives/IP/minute
- ✅ **Room ID cryptographique** - 32 bytes non prédictible
- ✅ **Auto-destruction** - rooms expirées après 10 minutes
- ✅ **Limite de participants** - strictement 2 par room
- ✅ **Vérification émetteur** - seul l'émetteur autorisé peut envoyer

### Mesures anti-analyse
- ✅ **Taille de chunks uniforme** (padding aléatoire)
- ✅ **Métadonnées chiffrées** (pas d'analyse de patterns)
- ✅ **Sessions éphémères** (destruction après transfert)
- ✅ **Timestamps minimaux** (limite le profilage temporel)

## Architecture de sécurité

### Flux de chiffrement
1. **Émetteur**: 
   - Génère AES-GCM 256 bits + HMAC-SHA256 côté client
   - Crée code: `ROOM_ID::CLÉ_AES_BASE64::CLÉ_HMAC_BASE64`
   - Chiffre métadonnées (nom, taille, type, timestamp)
   - Chiffre chaque chunk avec padding aléatoire
   - Signe chaque chunk avec HMAC
   - Serveur reçoit uniquement ciphertext + signatures

2. **Récepteur**:
   - Extrait clés AES et HMAC du code
   - Vérifie séquence des chunks (anti-rejeu)
   - Vérifie signature HMAC de chaque chunk
   - Déchiffre métadonnées et chunks côté client
   - Retire padding et reconstruit fichier

3. **Serveur**:
   - Ne génère PAS de clés cryptographiques
   - Relaye uniquement données chiffrées + signatures
   - Applique rate limiting et timeouts
   - Détruit automatiquement les sessions
   - Ne peut PAS déchiffrer ou modifier les données

### Chiffrement
- **Algorithme**: AES-GCM (AEAD - Authenticated Encryption with Associated Data)
- **Clé AES**: 256 bits générée côté client (Web Crypto API)
- **Clé HMAC**: SHA-256 générée côté client
- **IV/Nonce**: 96 bits unique aléatoire par chunk
- **Taille chunk**: 64 KB (65536 bytes)
- **Structure chunk**: 4 bytes (taille réelle) + données → padding → chiffrement
- **Padding uniforme**: Tous chunks paddés à CHUNK_SIZE + 4 = 65540 bytes
- **Ciphertext**: Taille uniforme pour tous les chunks (plein ou partiel)
- **Authentification**: HMAC-SHA256 sur (ciphertext + sequence)

### Protection contre les attaques

#### Attaques réseau
- **Man-in-the-Middle**: Impossible - clés jamais transmises au serveur
- **Traffic Analysis**: Chunks de taille uniforme masquent le pattern
- **Replay Attack**: Séquençage strict avec vérification côté client
- **Injection**: Signature HMAC vérifie intégrité de chaque chunk

#### Attaques serveur
- **Serveur compromis**: Ne peut pas déchiffrer (pas les clés)
- **Logging**: Métadonnées chiffrées, aucune info sensible en clair
- **Timing**: Chunks uniformes réduisent le fingerprinting

#### Attaques bruteforce
- **Room ID**: 32 bytes (256 bits) = 2^256 possibilités
- **Rate limiting**: 10 tentatives max par IP/minute
- **Timeout**: Room auto-détruite après 10 minutes

## Architecture technique

### Backend (Python + Flask)
- **Framework**: Flask avec Flask-SocketIO
- **Rôle**: Relais de signalisation uniquement (serveur aveugle)
- **Communication**: WebSocket temps réel
- **Sécurité**: Headers HTTP, rate limiting, auto-cleanup
- **Protection**: Vérification émetteur, limite participants

### Frontend (HTML/CSS/JavaScript)
- **Design**: Interface moderne avec dégradés violets chaleureux
- **Responsive**: Compatible mobile et desktop
- **Chiffrement**: Web Crypto API (AES-GCM + HMAC)
- **Communication**: Socket.IO client pour WebSocket
- **Transfert**: Chunks uniformes de 64KB avec padding

## Structure du projet
```
.
├── main.py                 # Backend Flask - relais sécurisé
├── templates/
│   └── index.html         # Interface utilisateur
├── static/
│   ├── css/
│   │   └── style.css      # Styles modernes
│   └── js/
│       └── app.js         # Chiffrement E2E + HMAC
├── pyproject.toml         # Configuration Python/uv
└── replit.md             # Documentation sécurité
```

## Comment utiliser l'application

### Pour envoyer un fichier:
1. Cliquer sur "Envoyer un fichier"
2. Sélectionner le fichier à transférer
3. Un code de connexion sera généré (contient clés AES + HMAC)
4. **Partager ce code via canal sécurisé** (Signal, WhatsApp chiffré, etc.)
5. Attendre connexion du destinataire
6. Transfert chiffré démarre automatiquement

### Pour recevoir un fichier:
1. Cliquer sur "Recevoir un fichier"
2. Entrer le code de connexion reçu
3. Se connecter
4. Vérifications de sécurité automatiques (HMAC, séquence)
5. Fichier se télécharge et se déchiffre automatiquement

### ⚠️ Important - Partage du code
Le code contient les clés de chiffrement et d'authentification. **Utilisez un canal sécurisé**:
- ✅ **Recommandé**: Signal, WhatsApp (chiffré), Telegram secret chat
- ✅ **Acceptable**: SMS (pour données peu sensibles)
- ❌ **Éviter**: Email non chiffré, Slack, Discord (pour données sensibles)

## Configuration de sécurité

### Limites et timeouts
- **Taille max fichier**: 500 MB
- **Taille chunk**: 64 KB (65536 bytes)
- **Taille chunk paddé**: 65540 bytes (chunk + header 4 bytes)
- **Taille ciphertext**: Uniforme pour tous les chunks
- **Timeout room**: 10 minutes (auto-destruction)
- **Rate limit**: 10 tentatives par IP par minute
- **Participants max**: 2 par room (émetteur + récepteur)
- **Room ID**: 32 bytes (256 bits d'entropie)

### Headers de sécurité HTTP
- `Content-Security-Policy`: Strict CSP limitant scripts/styles
- `Strict-Transport-Security`: HSTS pour forcer HTTPS
- `X-Frame-Options`: Protection contre clickjacking
- `X-Content-Type-Options`: Protection contre MIME sniffing
- `Referrer-Policy`: Pas de referrer pour vie privée
- `Permissions-Policy`: Désactivation géolocalisation/caméra/micro

## Technologies utilisées
- **Python 3.11**
- **Flask** - Framework web
- **Flask-SocketIO** - WebSocket support
- **Flask-CORS** - Gestion CORS
- **Web Crypto API** - AES-GCM + HMAC natif navigateur
- **Socket.IO** - Communication temps réel

## Déploiement
L'application est configurée pour Replit avec:
- Workflow "SendIT" auto-start
- Port 5000 exposé en webview
- Mode debug développement (désactiver en production)

## Notes de développement
- Erreurs LSP `request.sid` ignorables (Flask-SocketIO dynamique)
- `allow_unsafe_werkzeug=True` dev only (production: gunicorn/uwsgi)
- Timeouts WebSocket 120s pour gros fichiers
- Backend sans logique crypto (sécurité par design)

## Modèle de menace

### Adversaires protégés
- ✅ **Attaquant réseau passif**: Voit uniquement ciphertext
- ✅ **Attaquant réseau actif**: HMAC + séquençage prévient modification
- ✅ **Serveur compromis**: Ne peut pas déchiffrer (pas les clés)
- ✅ **Provider cloud**: Données chiffrées, métadonnées chiffrées
- ✅ **Forensics post-mortem**: Sessions éphémères auto-détruites

### Limitations (non protégés)
- ❌ **Endpoint compromise**: Si navigateur compromis, clés exposées
- ❌ **Canal de partage**: Code partagé en clair vulnérable à l'interception
- ⚠️ **Chunk count**: Serveur peut compter les chunks (granularité 64KB seulement)
- ❌ **Legal compliance**: Pas de déni plausible ou destruction garantie
- ⚠️ **Relay architecture**: WebSocket passe par serveur (pas vrai P2P direct)

## Améliorations futures possibles
- WebRTC pour P2P direct (éliminer relais serveur)
- QR code pour partager code (éviter copier-coller)
- Vérification d'empreinte (fingerprint) mutuelle
- Perfect Forward Secrecy avec échange Diffie-Hellman
- Compression pré-chiffrement (réduction bande passante)
- Support multi-fichiers en une session
- Audit de sécurité par tiers indépendant
- Support Tor/I2P pour anonymat réseau
