# backend/security/auth.py
#
# POURQUOI CE FICHIER EXISTE :
#   C'est la Couche 4 — Authentication + RBAC.
#   Il fait trois choses :
#   1. Définir les rôles et leurs permissions
#   2. Créer et vérifier les tokens JWT
#   3. Fournir des fonctions de dépendance pour les routes FastAPI
#
# POSITION DANS L'ARCHITECTURE :
#   Frontend → HTTP POST /auth/login
#   → [ICI] auth.py vérifie email+password → retourne JWT
#
#   Frontend → HTTP POST /api/v1/generate  (avec JWT dans le header)
#   → [ICI] auth.py vérifie le JWT → extrait le rôle
#   → pipeline_generator.py

import os
import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from dataclasses import dataclass
from typing import Optional

from jose import JWTError, jwt
import bcrypt as _bcrypt

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# CONFIGURATION JWT
#
# [SECURITY] SECRET_KEY doit être longue et aléatoire en production.
# Générée avec : python -c "import secrets; print(secrets.token_hex(32))"
# Elle est lue depuis .env — jamais hardcodée dans le code.
#
# [WHY ALGORITHM HS256]
# HS256 = HMAC-SHA256 — algorithme symétrique.
# Le même secret signe ET vérifie le token.
# Suffisant pour un service où le backend est le seul à vérifier.
# RS256 (asymétrique) serait nécessaire si plusieurs services
# devaient vérifier les tokens indépendamment.
#
# [WHY 30 minutes]
# Un token qui expire vite limite la fenêtre d'attaque si volé.
# Si l'attaquant vole le token, il n'a que 30 min pour l'utiliser.
# ----------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# ----------------------------------------------------------------
# RÔLES — Enum Python
#
# [WHY Enum et pas des strings]
# Avec des strings : role="admin" ou role="Admin" ou role="ADMIN"
# → fautes de frappe possibles, comparaisons fragiles
# Avec Enum : UserRole.ADMIN → valeur fixe, l'IDE autocomplète
# → impossible de faire une faute de frappe
# ----------------------------------------------------------------
class UserRole(str, Enum):
    DEVELOPER  = "developer"
    DEVOPS_LEAD = "devops_lead"
    ARCHITECTE = "architecte"
    ADMIN      = "admin"


# ----------------------------------------------------------------
# PERMISSIONS PAR RÔLE
#
# Chaque rôle est associé à un ensemble d'actions autorisées.
# On utilise un set() (ensemble) pour les permissions :
# "action" in ROLE_PERMISSIONS[role] → O(1), très rapide
# ----------------------------------------------------------------
ROLE_PERMISSIONS = {
    UserRole.DEVELOPER: {
        "generate_pipeline",    # générer un Jenkinsfile
        "view_history",         # voir l'historique de ses propres pipelines
    },
    UserRole.DEVOPS_LEAD: {
        "generate_pipeline",
        "view_history",
        "deploy_staging",       # déclencher un déploiement sur staging
        "view_all_history",     # voir l'historique de tous les utilisateurs
    },
    UserRole.ARCHITECTE: {
        "generate_pipeline",
        "view_history",
        "deploy_staging",
        "deploy_production",    # déclencher un déploiement en production
        "view_all_history",
        "view_metrics",         # accéder aux métriques Prometheus/Grafana
    },
    UserRole.ADMIN: {
        "generate_pipeline",
        "view_history",
        "deploy_staging",
        "deploy_production",
        "view_all_history",
        "view_metrics",
        "manage_users",         # créer/modifier/supprimer des comptes
        "admin_infrastructure", # accès complet à l'infrastructure
    },
}


# ----------------------------------------------------------------
# UTILISATEURS EN DUR — Base de données simulée
#
# [WHY pas une vraie base de données pour l'instant]
# En Phase 5 on connectera une vraie DB (SQLite ou PostgreSQL).
# Pour l'instant, ces utilisateurs hardcodés permettent de tester
# l'authentification sans infrastructure supplémentaire.
#
# [SECURITY] Les mots de passe sont stockés hashés avec bcrypt.
# Pour générer un hash : python -c "import bcrypt as _bcrypt;
# ctx = CryptContext(schemes=['bcrypt']); print(ctx.hash('monmotdepasse'))"
#
# Mots de passe en clair pour les tests :
#   admin123     → pour l'admin
#   devops123    → pour le devops_lead
#   dev123       → pour le developer
# ----------------------------------------------------------------
FAKE_USERS_DB = {
    "admin@nextgen.local": {
        "user_id": "usr_001",
        "email": "admin@nextgen.local",
        # [SECURITY] Jamais stocker le mot de passe en clair
        # Ce hash correspond à "admin123"
        "hashed_password": "$2b$12$RmbmoV9YuRvyPvzo6meBdeQ/M7jujidJN52LQpc1C2tln3jKbaLq2",
        "role": UserRole.ADMIN,
        "is_active": True,
    },
    "devops@nextgen.local": {
        "user_id": "usr_002",
        "email": "devops@nextgen.local",
        # Hash de "devops123"
        "hashed_password": "$2b$12$GmpZe96XDoFwALfpfAlM8uqKC8.yApI1.Dgan8gFEptZgvF4AcMB6",
        "role": UserRole.DEVOPS_LEAD,
        "is_active": True,
    },
    "dev@nextgen.local": {
        "user_id": "usr_003",
        "email": "dev@nextgen.local",
        # Hash de "dev123"
        "hashed_password": "$2b$12$XopmNVGR4rPqB7G9ej24X.xX65y04kCfZqy1M.bAxEtO7mbJx.EY6",
        "role": UserRole.DEVELOPER,
        "is_active": True,
    },
}


# ----------------------------------------------------------------
# BCRYPT — Hashing des mots de passe
#
# [WHY bcrypt et pas MD5 ou SHA256]
# MD5/SHA256 sont des fonctions RAPIDES → un attaquant peut tester
# des milliards de mots de passe par seconde (brute force).
# bcrypt est INTENTIONNELLEMENT LENT (cost factor = 12 rounds).
# Avec cost=12, hacher un mot de passe prend ~250ms.
# Un attaquant peut tester seulement ~4 mots de passe/seconde.
# C'est le même calcul mais il protège si la base de données est volée.
# ----------------------------------------------------------------
# Utilisation directe de bcrypt sans passlib (meilleure compatibilité)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Vérifie qu'un mot de passe en clair correspond au hash stocké.
    bcrypt est une fonction à sens unique — on compare les hashs.
    """
    try:
        return _bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def hash_password(password: str) -> str:
    """Hash un mot de passe avec bcrypt (cost=12)."""
    hashed = _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


# ----------------------------------------------------------------
# JWT — Création et vérification des tokens
# ----------------------------------------------------------------

def create_access_token(user_id: str, email: str, role: UserRole) -> str:
    """
    Crée un JWT signé contenant l'identité et le rôle de l'utilisateur.

    Structure du payload (partie décodable du JWT) :
    {
        "sub": "usr_001",           ← subject = user_id
        "email": "admin@nextgen.local",
        "role": "admin",
        "exp": 1234567890           ← timestamp d'expiration
    }

    [SECURITY] Le payload JWT est encodé en base64 mais PAS chiffré.
    N'importe qui peut décoder le payload sans connaître le secret.
    Ne jamais mettre de mot de passe ou secret dans le payload.
    Ce qui est protégé c'est la SIGNATURE — on ne peut pas
    modifier le payload sans invalider la signature.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": user_id,
        "email": email,
        "role": role.value,     # .value pour avoir la string "admin" et pas l'enum
        "exp": expire,
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    logger.info(f"JWT created | user_id={user_id} | role={role.value}")
    return token


@dataclass
class TokenData:
    """Données extraites d'un JWT valide."""
    user_id: str
    email: str
    role: UserRole


def verify_token(token: str) -> Optional[TokenData]:
    """
    Vérifie et décode un JWT.

    Retourne TokenData si le token est valide.
    Retourne None si le token est expiré, invalide, ou falsifié.

    [SECURITY] jose vérifie automatiquement :
    - La signature : le token n'a pas été modifié
    - L'expiration : le token n'est pas expiré (champ "exp")
    - L'algorithme : correspond à ALGORITHM défini
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        user_id = payload.get("sub")
        email = payload.get("email")
        role_str = payload.get("role")

        if not user_id or not role_str:
            logger.warning("JWT missing required fields")
            return None

        # [SECURITY] Vérifier que le rôle dans le token est un rôle valide
        # Un attaquant pourrait essayer de mettre role="superadmin" dans
        # un token auto-fabriqué — mais sans le SECRET_KEY la signature
        # serait invalide et jwt.decode() lèverait JWTError
        try:
            role = UserRole(role_str)
        except ValueError:
            logger.warning(f"JWT contains invalid role: {role_str}")
            return None

        return TokenData(user_id=user_id, email=email, role=role)

    except JWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        return None


# ----------------------------------------------------------------
# AUTHENTIFICATION — Vérifier email + password
# ----------------------------------------------------------------

def authenticate_user(email: str, password: str) -> Optional[dict]:
    """
    Vérifie les credentials et retourne l'utilisateur si valide.

    Retourne None si :
    - L'email n'existe pas
    - Le mot de passe est incorrect
    - Le compte est désactivé

    [SECURITY] On retourne le même message d'erreur dans tous les cas
    ("Email ou mot de passe incorrect") pour ne pas révéler si
    l'email existe dans la base. C'est l'User Enumeration Prevention.
    Un attaquant ne sait pas si c'est l'email ou le mot de passe qui est faux.
    """
    user = FAKE_USERS_DB.get(email)

    # [SECURITY] Même si l'utilisateur n'existe pas, on appelle quand même
    # verify_password() avec un hash dummy pour que le temps de réponse
    # soit identique qu'il existe ou non (protection contre timing attacks)
    if not user:
        _bcrypt.checkpw(b"dummy", b"$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW")
        logger.warning(f"Login attempt with unknown email: {email}")
        return None

    if not verify_password(password, user["hashed_password"]):
        logger.warning(f"Failed login attempt | user_id={user['user_id']}")
        return None

    if not user["is_active"]:
        logger.warning(f"Login attempt on disabled account | user_id={user['user_id']}")
        return None

    logger.info(f"Successful login | user_id={user['user_id']} | role={user['role'].value}")
    return user


# ----------------------------------------------------------------
# VÉRIFICATION DES PERMISSIONS
# ----------------------------------------------------------------

def has_permission(role: UserRole, action: str) -> bool:
    """
    Vérifie si un rôle a la permission d'effectuer une action.

    Usage dans les routes :
        token_data = verify_token(jwt_token)
        if not has_permission(token_data.role, "deploy_production"):
            raise HTTPException(403, "Accès refusé")

    [WHY cette fonction et pas vérifier directement le rôle]
    Si on vérifie le rôle directement :
        if role == UserRole.ADMIN or role == UserRole.ARCHITECTE:
    Quand on ajoute un nouveau rôle, il faut mettre à jour
    chaque condition dans tout le code.

    Avec has_permission(), on met à jour seulement ROLE_PERMISSIONS.
    Toutes les vérifications sont automatiquement à jour.
    """
    permissions = ROLE_PERMISSIONS.get(role, set())
    allowed = action in permissions

    if not allowed:
        logger.warning(
            f"Permission denied | role={role.value} | action={action}"
        )
    return allowed