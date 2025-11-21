# Utilise une image officielle Python comme base
FROM python:3.11-slim

# Définis le répertoire de travail dans le conteneur
WORKDIR /app

# Copie les fichiers du projet dans le conteneur
COPY . .

# Installe les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Expose le port par défaut de Flask (8080 ou 5000, selon votre config)
# C'est optionnel mais recommandé pour la documentation
EXPOSE 5000 

# Commande pour lancer l'application Flask
# TRÈS IMPORTANT : utiliser 0.0.0.0 pour écouter depuis l'extérieur du conteneur
#CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
# Si vous lancez avec Python directement, utilisez :
CMD ["python", "main.py", "--host=0.0.0.0", "--port=5000"]