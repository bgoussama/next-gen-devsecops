# backend/api/routes.py
# VERSION COMPLÈTE — Phase 7 + Phase 8
#
# ROUTES :
#   POST /auth/login            → connexion JWT
#   POST /api/v1/generate       → génère 1 Jenkinsfile (Couches 1+2+3)
#   POST /api/v1/generate/all   → génère 4 artefacts + push GitHub
#   GET  /api/v1/history        → historique des pipelines
#   GET  /health                → état du serveur

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dataclasses import asdict
from pydantic import BaseModel, Field, field_validator
from typing import Any
import logging

from security.auth import (
    authenticate_user,
    create_access_token,
    verify_token,
    has_permission,
    TokenData,
)
from services.pipeline_generator import generate_secure_pipeline
from services.artifact_generator import generate_all_artifacts
from services.github_pusher import push_artifacts_to_github
from services.report_store import save_report, get_all_reports
from services.threat_analyzer import analyze_threats
from utils.history_manager import save_to_history, get_user_history

logger = logging.getLogger(__name__)
router = APIRouter()
security = HTTPBearer()


# ----------------------------------------------------------------
# MODÈLES PYDANTIC
# ----------------------------------------------------------------

class LoginRequest(BaseModel):
    email: str
    password: str

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


class ArtifactsResponse(BaseModel):
    """
    Réponse pour la génération des 4 artefacts.
    github_branch_url : URL de la branche créée sur GitHub (vide si push échoué)
    """
    success: bool
    jenkinsfile: str = ""
    terraform: str = ""
    dockerfile: str = ""
    k8s_manifest: str = ""
    error_message: str = ""
    tokens_used: int = 0
    github_branch_url: str = ""   # ← Phase 8 — URL de la branche GitHub
    threat_score: int = 0
    threat_risk_level: str = ""
    threat_techniques: list = Field(default_factory=list)
    threat_recommendations: list = Field(default_factory=list)
    threat_summary: str = ""


class ThreatAnalysisRequest(BaseModel):
    jenkinsfile: str = ""
    terraform: str = ""
    dockerfile: str = ""
    k8s_manifest: str = ""


class PipelineReportRequest(BaseModel):
    branch: str
    build_number: Any
    status: str
    duration_ms: int | float = 0
    timestamp: str | None = None
    sonarqube_url: str | None = None
    github_branch_url: str | None = None
    deployed_url: str | None = None  # URL EC2 apres terraform output

    @field_validator("status")
    @classmethod
    def status_allowed(cls, v):
        if v not in {"SUCCESS", "FAILURE"}:
            raise ValueError("Le statut doit etre SUCCESS ou FAILURE")
        return v


# ----------------------------------------------------------------
# DÉPENDANCE JWT
# ----------------------------------------------------------------

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> TokenData:
    """
    Extrait et vérifie le JWT depuis le header Authorization.
    Retourne TokenData ou lève une erreur 401.
    """
    token = credentials.credentials
    token_data = verify_token(token)

    if not token_data:
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
    Authentification — retourne un JWT si les credentials sont valides.

    [SECURITY] Message d'erreur générique pour éviter la User Enumeration.
    On ne révèle pas si c'est l'email ou le mot de passe qui est faux.
    """
    user = authenticate_user(request.email, request.password)

    if not user:
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
# Génère un Jenkinsfile avec les 3 couches de sécurité complètes
# ----------------------------------------------------------------

@router.post("/api/v1/generate", response_model=GenerateResponse, tags=["Pipeline"])
async def generate_pipeline(
    request: GenerateRequest,
    token_data: TokenData = Depends(get_current_user),
):
    """
    Génère un Jenkinsfile sécurisé depuis un prompt.

    Flux complet :
    Couche 1 → validate_prompt() — regex injection
    Couche 2 → groq_client()     — system prompt hardened
    Couche 3 → validate_output() — scan réponse LLM
    Couche 4 → RBAC + JWT        — vérification rôle
    """
    if not has_permission(token_data.role, "generate_pipeline"):
        raise HTTPException(
            status_code=403,
            detail=f"Rôle '{token_data.role.value}' non autorisé.",
        )

    logger.info(f"Generate | user={token_data.user_id} | role={token_data.role.value}")

    result = generate_secure_pipeline(
        user_prompt=request.prompt,
        user_id=token_data.user_id,
    )

    # [NEW] Sauvegarde historique pour Monitoring (Phase 7)
    save_to_history(
        user_id=token_data.user_id,
        prompt=request.prompt,
        status="success" if result.success else "error",
        tokens_used=result.tokens_used,
        type="Jenkinsfile",
        error_message=result.error_message
    )

    return GenerateResponse(
        success=result.success,
        pipeline_content=result.pipeline_content,
        error_message=result.error_message,
        tokens_used=result.tokens_used,
        generation_time_ms=result.generation_time_ms,
    )


# ----------------------------------------------------------------
# ROUTE 3 - POST /api/v1/analyze/threats
# Analyse MITRE ATT&CK des artefacts fournis
# ----------------------------------------------------------------

@router.post("/api/v1/analyze/threats", tags=["Threat Intelligence"])
async def analyze_artifact_threats(
    request: ThreatAnalysisRequest,
    token_data: TokenData = Depends(get_current_user),
):
    """
    Analyse les artefacts DevSecOps avec une grille MITRE ATT&CK.

    JWT requis : l'analyse manipule des artefacts potentiellement sensibles.
    """
    if not has_permission(token_data.role, "generate_pipeline"):
        raise HTTPException(
            status_code=403,
            detail=f"RÃ´le '{token_data.role.value}' non autorisÃ©.",
        )

    # Analyse locale : aucun artefact n'est envoye a un service externe.
    result = analyze_threats(
        jenkinsfile=request.jenkinsfile,
        terraform=request.terraform,
        dockerfile=request.dockerfile,
        k8s_manifest=request.k8s_manifest,
    )
    return asdict(result)


# ----------------------------------------------------------------
# ROUTE 4 — POST /api/v1/generate/all
# Génère les 4 artefacts + push automatique sur GitHub
# ----------------------------------------------------------------

@router.post("/api/v1/generate/all", response_model=ArtifactsResponse, tags=["Pipeline"])
async def generate_all(
    request: GenerateRequest,
    token_data: TokenData = Depends(get_current_user),
):
    """
    Génère les 4 artefacts DevSecOps et les pousse sur GitHub.

    Flux :
    1. Vérification RBAC (Couche 4)
    2. Validation du prompt (Couche 1)
    3. Génération des 4 artefacts via Groq (Couche 2)
    4. Push automatique sur GitHub dans une branche dédiée (Phase 8)
    5. Retour des artefacts + URL GitHub au frontend

    [WHY on ne bloque pas si GitHub échoue]
    Les artefacts ont été générés avec succès.
    Un problème GitHub (token expiré, réseau) ne doit pas empêcher
    l'utilisateur de voir et télécharger ses fichiers.
    On log l'erreur mais on retourne quand même les artefacts.
    """
    # Couche 4 — RBAC
    if not has_permission(token_data.role, "generate_pipeline"):
        raise HTTPException(
            status_code=403,
            detail=f"Rôle '{token_data.role.value}' non autorisé.",
        )

    # Couche 1 — Validation du prompt
    from security.prompt_guard import validate_prompt
    validation = validate_prompt(request.prompt)
    if not validation.is_valid:
        logger.warning(
            f"Prompt rejected | user={token_data.user_id} | "
            f"reason={validation.reason} | score={validation.risk_score}"
        )
        return ArtifactsResponse(
            success=False,
            error_message=validation.reason,
        )

    logger.info(f"Generate all | user={token_data.user_id} | role={token_data.role.value}")

    # Couche 2 — Génération des 4 artefacts via Groq
    result = generate_all_artifacts(request.prompt)

    if not result.success:
        logger.error(f"Generation failed | user={token_data.user_id} | {result.error_message}")
        return ArtifactsResponse(
            success=False,
            error_message=result.error_message,
        )

    # Phase 8 — Push automatique sur GitHub
    # [WHY après la vérification de succès]
    # On ne pousse sur GitHub que si la génération a réussi.
    # Inutile de créer une branche vide.
    push_result = push_artifacts_to_github(
        jenkinsfile=result.jenkinsfile,
        terraform=result.terraform,
        dockerfile=result.dockerfile,
        k8s_manifest=result.k8s_manifest,
        user_id=token_data.user_id,
        prompt_summary=request.prompt[:80],
    )

    if push_result.success:
        logger.info(
            f"GitHub push success | branch={push_result.branch_name} | "
            f"files={push_result.files_pushed}"
        )
    else:
        logger.warning(
            f"GitHub push failed (non-blocking) | "
            f"user={token_data.user_id} | error={push_result.error_message}"
        )

    # [NEW] Sauvegarde historique pour Monitoring (Phase 7)
    save_to_history(
        user_id=token_data.user_id,
        prompt=request.prompt,
        status="success",
        tokens_used=result.tokens_used,
        type="Full Stack (4 artefacts)",
        error_message=""
    )

    # Threat Intelligence MITRE ATT&CK calculee automatiquement sur les artefacts generes.
    threat_result = analyze_threats(
        jenkinsfile=result.jenkinsfile,
        terraform=result.terraform,
        dockerfile=result.dockerfile,
        k8s_manifest=result.k8s_manifest,
    )

    return ArtifactsResponse(
        success=True,
        jenkinsfile=result.jenkinsfile,
        terraform=result.terraform,
        dockerfile=result.dockerfile,
        k8s_manifest=result.k8s_manifest,
        tokens_used=result.tokens_used,
        github_branch_url=push_result.branch_url if push_result.success else "",
        threat_score=threat_result.score,
        threat_risk_level=threat_result.risk_level,
        threat_techniques=threat_result.techniques,
        threat_recommendations=threat_result.recommendations,
        threat_summary=threat_result.summary,
    )


# ----------------------------------------------------------------
# ROUTE 4 — POST /api/v1/pipeline/report (publique Jenkins)
# ----------------------------------------------------------------

@router.post("/api/v1/pipeline/report", tags=["Pipeline"])
async def receive_pipeline_report(request: PipelineReportRequest):
    """
    Recoit un rapport Jenkins sans JWT.
    Jenkins appelle cette route depuis le stage Deploy Report.
    """
    report = save_report(request.model_dump(exclude_none=True))
    logger.info(
        f"Jenkins report saved | id={report['id']} | "
        f"branch={report['branch']} | status={report['status']}"
    )
    return {"success": True, "id": report["id"]}


# ----------------------------------------------------------------
# ROUTE 5 — GET /api/v1/pipeline/reports (JWT requis)
# ----------------------------------------------------------------

@router.get("/api/v1/pipeline/reports", tags=["Pipeline"])
async def list_pipeline_reports(
    token_data: TokenData = Depends(get_current_user),
):
    """Retourne tous les rapports Jenkins, du plus recent au plus ancien."""
    return {"reports": get_all_reports()}


# ----------------------------------------------------------------
# ROUTE 6 — GET /api/v1/history
# ----------------------------------------------------------------

@router.get("/api/v1/history", tags=["Pipeline"])
async def get_history(
    token_data: TokenData = Depends(get_current_user),
):
    """
    Retourne l'historique des pipelines générés.
    Lecture depuis le fichier JSON local (Phase 7).
    """
    if not has_permission(token_data.role, "view_history"):
        raise HTTPException(status_code=403, detail="Accès refusé.")

    pipelines = get_user_history(token_data.user_id, token_data.role.value)

    return {
        "user_id": token_data.user_id,
        "role": token_data.role.value,
        "pipelines": pipelines,
    }


# ----------------------------------------------------------------
# ROUTE 7 — GET /health (publique)
# ----------------------------------------------------------------

@router.get("/health", tags=["Monitoring"])
async def health():
    """
    Endpoint de santé — public, pas de JWT requis.
    Utilisé par Docker, Prometheus, Jenkins pour vérifier l'état.
    """
    return {
        "status": "healthy",
        "service": "next-gen-devsecops-backend",
        "version": "1.0.0",
    }
