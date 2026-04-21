# backend/api/routes.py
#
# POURQUOI CE FICHIER EXISTE :
#   Ce sont les routes HTTP — les "portes d'entrée" du backend.
#   Chaque route correspond à une URL que le frontend peut appeler.
#
# ROUTES DÉFINIES :
#   POST /auth/login          → connexion, retourne un JWT
#   POST /api/v1/generate     → générer un pipeline (authentifié)
#   GET  /api/v1/history      → voir ses pipelines générés (authentifié)
#   GET  /api/v1/health       → état du serveur (public)
#
# [WHY FastAPI et pas Flask pour les routes]
# FastAPI valide automatiquement le format des requêtes via Pydantic.
# Si le frontend envoie {"prompt": 123} (nombre au lieu de string),
# FastAPI retourne une erreur 422 automatiquement — sans code supplémentaire.

from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
import logging

from backend.security.auth import (
    authenticate_user,
    create_access_token,
    verify_token,
    has_permission,
    TokenData,
)
from backend.services.pipeline_generator import generate_secure_pipeline

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# ROUTER
#
# [WHY APIRouter et pas app directement]
# APIRouter permet de grouper les routes par domaine.
# En main.py : app.include_router(router)
# Si demain on veut une v2 : app.include_router(router_v2, prefix="/v2")
# ----------------------------------------------------------------
router = APIRouter()
security = HTTPBearer()  # Lit le token depuis le header "Authorization: Bearer <token>"


# ----------------------------------------------------------------
# MODÈLES PYDANTIC — Validation automatique des données
#
# [WHY Pydantic]
# Pydantic valide le format des données avant que ton code les touche.
# Si le frontend envoie {"prompt": ""} (vide), Pydantic lève une erreur
# avant même d'appeler validate_prompt() — double protection.
# ----------------------------------------------------------------

class LoginRequest(BaseModel):
    email: str
    password: str

    # [SECURITY] Empêcher les mots de passe vides
    @field_validator("password")
    @classmethod
    def password_not_empty(cls, v):
        if not v or len(v) < 3:
            raise ValueError("Mot de passe trop court")
        return v


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: str


class GenerateRequest(BaseModel):
    prompt: str

    # [SECURITY] Validation côté serveur — même si le frontend valide,
    # on revalide ici. Le client-side validation c'est de l'UX,
    # le server-side validation c'est de la sécurité.
    @field_validator("prompt")
    @classmethod
    def prompt_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("Le prompt ne peut pas être vide")
        if len(v) > 2000:
            raise ValueError("Le prompt ne peut pas dépasser 2000 caractères")
        return v.strip()


class GenerateResponse(BaseModel):
    success: bool
    pipeline_content: str = ""
    error_message: str = ""
    tokens_used: int = 0
    generation_time_ms: int = 0


# ----------------------------------------------------------------
# DÉPENDANCE FastAPI — Extraction et vérification du JWT
#
# [WHY Depends()]
# FastAPI injecte automatiquement cette fonction dans les routes
# qui en ont besoin. Si le token est invalide, la route retourne
# 401 automatiquement — sans code supplémentaire dans chaque route.
#
# Usage dans une route :
#   async def ma_route(token_data: TokenData = Depends(get_current_user)):
#       # token_data est automatiquement vérifié avant d'arriver ici
# ----------------------------------------------------------------
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> TokenData:
    """
    Dépendance FastAPI : extrait et vérifie le JWT du header Authorization.

    Le header attendu : Authorization: Bearer eyJhbGc...

    [SECURITY] HTTPBearer() extrait automatiquement le token après "Bearer ".
    On vérifie ensuite la validité avec verify_token().
    """
    token = credentials.credentials
    token_data = verify_token(token)

    if not token_data:
        # [SECURITY] 401 Unauthorized — le token est invalide ou expiré
        # On ne dit pas pourquoi exactement (expiré ? falsifié ?)
        # pour ne pas aider un attaquant
        raise HTTPException(
            status_code=401,
            detail="Token invalide ou expiré. Reconnecte-toi.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data


# ----------------------------------------------------------------
# ROUTE 1 — POST /auth/login
# ----------------------------------------------------------------

@router.post("/auth/login", response_model=LoginResponse, tags=["Auth"])
async def login(request: LoginRequest):
    """
    Authentification — vérifie email + password, retourne un JWT.

    Le frontend stocke ce token et l'envoie dans chaque requête suivante
    dans le header : Authorization: Bearer <token>

    [SECURITY] On ne retourne JAMAIS le mot de passe dans la réponse.
    On retourne seulement le token, le rôle, et l'user_id.
    """
    user = authenticate_user(request.email, request.password)

    if not user:
        # [SECURITY] Message générique — ne révèle pas si c'est l'email
        # ou le mot de passe qui est faux (User Enumeration Prevention)
        raise HTTPException(
            status_code=401,
            detail="Email ou mot de passe incorrect.",
        )

    token = create_access_token(
        user_id=user["user_id"],
        email=user["email"],
        role=user["role"],
    )

    return LoginResponse(
        access_token=token,
        role=user["role"].value,
        user_id=user["user_id"],
    )


# ----------------------------------------------------------------
# ROUTE 2 — POST /api/v1/generate
# ----------------------------------------------------------------

@router.post("/api/v1/generate", response_model=GenerateResponse, tags=["Pipeline"])
async def generate_pipeline(
    request: GenerateRequest,
    token_data: TokenData = Depends(get_current_user),  # JWT obligatoire
):
    """
    Génère un pipeline CI/CD à partir d'un prompt en langage naturel.

    Flux :
    1. FastAPI vérifie le JWT via Depends(get_current_user)
    2. On vérifie que le rôle a la permission "generate_pipeline"
    3. On appelle pipeline_generator.generate_secure_pipeline()
       qui orchestre les 3 couches de sécurité
    4. On retourne le résultat

    [SECURITY] La route est protégée par deux niveaux :
    - Authentification : token JWT valide obligatoire
    - Autorisation : rôle avec permission "generate_pipeline"
    """
    # Vérification RBAC
    if not has_permission(token_data.role, "generate_pipeline"):
        raise HTTPException(
            status_code=403,
            detail=f"Ton rôle '{token_data.role.value}' n'a pas accès à cette fonctionnalité.",
        )

    logger.info(
        f"Generate request | user_id={token_data.user_id} | "
        f"role={token_data.role.value}"
    )

    # Appel de l'orchestrateur (Couches 1 + 2 + 3)
    result = generate_secure_pipeline(
        user_prompt=request.prompt,
        user_id=token_data.user_id,
    )

    return GenerateResponse(
        success=result.success,
        pipeline_content=result.pipeline_content,
        error_message=result.error_message,
        tokens_used=result.tokens_used,
        generation_time_ms=result.generation_time_ms,
    )


# ----------------------------------------------------------------
# ROUTE 3 — GET /api/v1/history
# ----------------------------------------------------------------

@router.get("/api/v1/history", tags=["Pipeline"])
async def get_history(
    token_data: TokenData = Depends(get_current_user),
):
    """
    Retourne l'historique des pipelines générés.

    Pour l'instant retourne une liste vide — sera connecté
    à une base de données en Phase suivante.

    [SECURITY] Chaque utilisateur ne voit que SES propres pipelines,
    sauf le devops_lead et admin qui ont "view_all_history".
    """
    if not has_permission(token_data.role, "view_history"):
        raise HTTPException(status_code=403, detail="Accès refusé.")

    # TODO Phase suivante : récupérer depuis la DB filtrée par user_id
    return {
        "user_id": token_data.user_id,
        "role": token_data.role.value,
        "pipelines": [],  # sera rempli quand on connecte une DB
    }


# ----------------------------------------------------------------
# ROUTE 4 — GET /health (publique — pas de JWT requis)
# ----------------------------------------------------------------

@router.get("/health", tags=["Monitoring"])
async def health():
    """
    Endpoint de santé étendu.
    Utilisé par Docker, Prometheus, et Jenkins pour vérifier l'état.
    """
    return {
        "status": "healthy",
        "service": "next-gen-devsecops-backend",
        "version": "1.0.0",
    }