# backend/Dockerfile
#
# POURQUOI UN MULTI-STAGE BUILD :
#   Stage 1 (builder) : installe toutes les dépendances dans un environnement temporaire
#   Stage 2 (runtime) : copie seulement le nécessaire → image finale plus petite et plus sûre
#   Avantage sécurité : les outils de build (pip, compilateurs) n'existent pas
#   dans l'image de production — surface d'attaque réduite.

# ---- Stage 1 : Installation des dépendances ----------------
FROM python:3.11-slim AS builder

WORKDIR /app

# Copier uniquement le requirements d'abord — optimisation du cache Docker.
# Si le code change mais pas les dépendances, cette couche est réutilisée
# et l'installation pip est sautée → build beaucoup plus rapide.
COPY requirements.txt .

# [SECURITY] --no-cache-dir : ne pas stocker le cache pip dans l'image
# --user : installation dans ~/.local pour ne pas contaminer le système
RUN pip install --no-cache-dir --user -r requirements.txt

# ---- Stage 2 : Image de production -------------------------
FROM python:3.11-slim AS runtime

# [SECURITY] Ne pas tourner en tant que root.
# Si l'application est compromise, l'attaquant n'a pas les droits root
# sur le conteneur — principe du moindre privilège.
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

# Copier les dépendances installées depuis le stage builder
COPY --from=builder /root/.local /home/appuser/.local

# Copier le code de l'application
COPY --chown=appuser:appgroup . .

# Appliquer l'utilisateur non-root
USER appuser

# [SECURITY] Variables d'environnement de sécurité Python
ENV PYTHONDONTWRITEBYTECODE=1   # Pas de fichiers .pyc (moins de surface d'attaque)
ENV PYTHONUNBUFFERED=1          # Logs en temps réel (pas de buffer)
ENV PATH=/home/appuser/.local/bin:$PATH

EXPOSE 8000

# Healthcheck : Docker vérifie que l'app répond toutes les 30s
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

# [WHY uvicorn et pas gunicorn] :
# uvicorn supporte async/await natif — crucial pour les appels à Groq API
# qui sont des I/O réseau. Gunicorn est synchrone par défaut.
# En production, on combinerait : gunicorn -k uvicorn.workers.UvicornWorker
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
