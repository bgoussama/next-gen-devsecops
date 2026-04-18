# backend/main.py
#
# POURQUOI CE FICHIER EXISTE :
#   C'est le point d'entrée de l'application FastAPI.
#   Il initialise le serveur, monte les routes, configure les middlewares
#   globaux (CORS, logging), et expose l'endpoint /health pour le monitoring.
#
# POURQUOI FASTAPI ET PAS FLASK :
#   FastAPI génère automatiquement la documentation Swagger (/docs),
#   supporte nativement async/await (crucial pour les appels à Groq API
#   et GitHub qui sont des I/O réseau), et valide les données avec Pydantic
#   — ce qui constitue une première couche de sécurité sur les inputs.

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import os

# [SECURITY] On configure le logging avant tout — si une erreur survient
# au démarrage, on veut pouvoir la tracer. Le niveau INFO en dev,
# WARNING en prod pour ne pas exposer trop d'infos dans les logs.
logging.basicConfig(
    level=logging.INFO if os.getenv("DEBUG", "False") == "True" else logging.WARNING,
    format="%(asctime)s — %(name)s — %(levelname)s — %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Next-Gen DevSecOps API",
    description="Plateforme de génération automatique de pipelines CI/CD sécurisés via IA",
    version="1.0.0",
    # [SECURITY] En production, désactiver la doc publique
    # docs_url=None si DEBUG=False
    docs_url="/docs" if os.getenv("DEBUG", "False") == "True" else None,
    redoc_url=None,
)

# ----------------------------------------------------------------
# CORS — Cross-Origin Resource Sharing
# [SECURITY] On liste explicitement les origines autorisées.
# Ne jamais mettre allow_origins=["*"] en production :
# cela autoriserait n'importe quel site à appeler l'API
# depuis le navigateur d'un utilisateur connecté.
# ----------------------------------------------------------------
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],   # Limiter aux méthodes nécessaires
    allow_headers=["Content-Type", "Authorization"],
)

# ----------------------------------------------------------------
# ROUTES — On importe les routers une fois les services prêts
# L'import est ici (et non au niveau module) pour éviter les
# circular imports entre les modules de sécurité.
# ----------------------------------------------------------------
# from api.routes import router as api_router
# app.include_router(api_router, prefix="/api/v1")
# NOTE : Décommenté à l'étape 2 quand les routes seront créées


@app.get("/health", tags=["Monitoring"])
async def health_check():
    """
    Endpoint de santé utilisé par :
    - Docker HEALTHCHECK
    - Prometheus pour vérifier que l'app répond
    - Jenkins pour valider le déploiement
    
    Retourne toujours 200 si l'app est démarrée.
    En Phase 7, on ajoutera des checks sur Redis et Groq API.
    """
    return {
        "status": "healthy",
        "service": "next-gen-devsecops-backend",
        "version": "1.0.0",
    }


@app.on_event("startup")
async def startup_event():
    """
    Exécuté au démarrage du serveur.
    En Phase 4, on initialisera ici :
    - La connexion Redis pour le rate limiting
    - Le pré-chargement du modèle LLM Guard
    - La vérification de la clé Groq API
    """
    logger.info("Next-Gen DevSecOps backend starting...")
    logger.info(f"Debug mode: {os.getenv('DEBUG', 'False')}")
    logger.info(f"Allowed origins: {ALLOWED_ORIGINS}")


@app.on_event("shutdown")
async def shutdown_event():
    """
    Exécuté à l'arrêt propre du serveur (SIGTERM de Docker/K8s).
    Permet de fermer proprement les connexions Redis, etc.
    """
    logger.info("Next-Gen DevSecOps backend shutting down...")
