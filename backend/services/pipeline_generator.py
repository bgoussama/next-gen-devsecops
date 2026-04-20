# backend/services/pipeline_generator.py
#
# POURQUOI CE FICHIER EXISTE :
#   C'est l'orchestrateur principal du backend.
#   Il reçoit le prompt brut du frontend et coordonne toutes les couches
#   de sécurité pour retourner un pipeline sécurisé ou une erreur claire.
#
# CE FICHIER NE FAIT PAS LE TRAVAIL LUI-MÊME :
#   Il délègue à :
#   - prompt_guard.py     (Couche 1 — valider l'input)
#   - groq_client.py      (Couche 2 — appeler le LLM)
#   - output_validator.py (Couche 3 — valider l'output)
#
# ANALOGIE :
#   Un chef de projet qui coordonne des experts.
#   Il ne code pas, ne sécurise pas, ne parle pas à Groq —
#   il s'assure que chaque expert fait son travail dans le bon ordre.
#
# PRINCIPE UTILISÉ — Single Responsibility :
#   pipeline_generator.py → orchestrer
#   prompt_guard.py       → valider input
#   groq_client.py        → appeler LLM
#   output_validator.py   → valider output
#   Chaque fichier a UNE responsabilité. On ne mélange pas.

import logging
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from backend.security.prompt_guard import validate_prompt
from backend.security.output_validator import validate_output
from backend.services.groq_client import generate_pipeline as call_groq

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------
# STRUCTURE DE RETOUR FINALE
#
# [WHY dataclass avec field(default=...)]
# Les champs avec une valeur par défaut doivent venir APRÈS
# les champs sans valeur par défaut — règle Python.
# field(default="") permet de respecter cette règle proprement.
# ----------------------------------------------------------------
@dataclass
class PipelineResult:
    """
    Résultat final retourné au frontend après toutes les couches.

    success=True  → pipeline généré, contenu dans `pipeline_content`
    success=False → erreur, message dans `error_message`
    """
    success: bool
    pipeline_content: str = field(default="")
    error_message: str = field(default="")

    # Métadonnées pour les logs et le monitoring (Couche 6)
    tokens_used: int = field(default=0)
    generation_time_ms: int = field(default=0)
    prompt_hash: str = field(default="")  # hash du prompt, jamais le texte brut
    risk_score: float = field(default=0.0)


def _hash_prompt(prompt: str) -> str:
    """
    Retourne un hash SHA-256 du prompt pour les logs d'audit.

    [SECURITY] On ne log JAMAIS le texte brut d'un prompt en production.
    Pourquoi ? Le prompt peut contenir des informations sensibles sur
    l'infrastructure de l'utilisateur. On log le hash qui permet de
    relier les événements sans exposer le contenu.

    Exemple :
        prompt = "Deploy app with secret_db_password_prod"
        hash   = "a3f2e1..." (irreversible — on ne peut pas retrouver le texte)
    """
    return hashlib.sha256(prompt.encode()).hexdigest()[:16]  # 16 premiers caractères suffisent


def generate_secure_pipeline(user_prompt: str, user_id: str = "anonymous") -> PipelineResult:
    """
    Fonction principale — orchestre toutes les couches de sécurité.

    Flux complet :
        1. Couche 1 : validate_prompt()     → bloquer les injections
        2. Couche 2 : call_groq()           → générer le pipeline via LLM
        3. Couche 3 : validate_output()     → vérifier la réponse du LLM

    Args:
        user_prompt : le texte saisi par l'utilisateur sur le frontend
        user_id     : identifiant de l'utilisateur (pour les logs Couche 6)
                      par défaut "anonymous" — sera remplacé par JWT en Phase 4

    Returns:
        PipelineResult avec success=True et le pipeline, ou success=False et l'erreur
    """
    # Démarrer le chronomètre — on mesure le temps total de génération
    # Cette métrique sera affichée dans le dashboard Grafana
    start_time = time.time()

    # Calculer le hash du prompt pour traçabilité
    prompt_hash = _hash_prompt(user_prompt)

    logger.info(
        f"Pipeline generation started | "
        f"user_id={user_id} | "
        f"prompt_hash={prompt_hash} | "
        f"prompt_length={len(user_prompt) if user_prompt else 0}"
    )

    # ----------------------------------------------------------------
    # ÉTAPE 1 — COUCHE 1 : VALIDATION DE L'INPUT
    #
    # On valide le prompt AVANT tout. Si c'est une injection,
    # on s'arrête ici — pas de token Groq consommé, pas de risque.
    #
    # [WHY fail-fast] Échouer tôt est moins coûteux qu'échouer tard.
    # Appeler Groq coûte des tokens et du temps (1-2 secondes).
    # Rejeter un prompt malveillant en 0.001 seconde avec regex = gratuit.
    # ----------------------------------------------------------------
    try:
        input_validation = validate_prompt(user_prompt)
    except Exception as e:
        # Une exception inattendue dans validate_prompt (jamais censé arriver
        # mais on défend contre tout)
        logger.error(f"Unexpected error in input validation | {e}")
        return PipelineResult(
            success=False,
            error_message="Erreur interne lors de la validation. Réessaie.",
            prompt_hash=prompt_hash,
        )

    if not input_validation.is_valid:
        # [SECURITY] Log avec le risk_score pour les alertes Grafana
        logger.warning(
            f"Input rejected | "
            f"user_id={user_id} | "
            f"prompt_hash={prompt_hash} | "
            f"reason={input_validation.reason} | "
            f"risk_score={input_validation.risk_score}"
        )
        return PipelineResult(
            success=False,
            error_message=input_validation.reason,
            prompt_hash=prompt_hash,
            risk_score=input_validation.risk_score,
        )

    logger.info(f"Input validation passed | prompt_hash={prompt_hash}")

    # ----------------------------------------------------------------
    # ÉTAPE 2 — COUCHE 2 : APPEL GROQ API
    #
    # Le prompt a passé la Couche 1. On l'envoie à Groq enveloppé
    # dans le SECURE_SYSTEM_PROMPT (défini dans groq_client.py).
    #
    # [WHY try/except RuntimeError]
    # groq_client.py lève RuntimeError après 3 retries échoués.
    # On l'attrape ici pour retourner une réponse propre au frontend
    # plutôt que laisser le serveur crasher avec une stack trace.
    # ----------------------------------------------------------------
    try:
        groq_result = call_groq(user_prompt)
    except RuntimeError as e:
        logger.error(
            f"Groq API failed | "
            f"user_id={user_id} | "
            f"prompt_hash={prompt_hash} | "
            f"error={str(e)}"
        )
        return PipelineResult(
            success=False,
            error_message=str(e),
            prompt_hash=prompt_hash,
        )
    except Exception as e:
        logger.error(f"Unexpected error calling Groq | {e}")
        return PipelineResult(
            success=False,
            error_message="Service LLM temporairement indisponible.",
            prompt_hash=prompt_hash,
        )

    generated_content = groq_result["content"]
    tokens_used = groq_result["tokens_used"]

    logger.info(
        f"Groq generation success | "
        f"prompt_hash={prompt_hash} | "
        f"tokens={tokens_used} | "
        f"attempts={groq_result['attempts']}"
    )

    # ----------------------------------------------------------------
    # ÉTAPE 3 — COUCHE 3 : VALIDATION DE L'OUTPUT
    #
    # On scanne ce que Groq a généré AVANT de le retourner.
    # Même si le prompt était légitime, Groq peut avoir produit
    # quelque chose de dangereux (credentials hardcodés, RCE, etc.)
    #
    # [WHY c'est nécessaire même avec un bon system prompt]
    # Les LLMs ne sont pas déterministes à 100%. Sur des millions
    # d'appels, certains génèrent des sorties inattendues.
    # La Couche 3 est le filet de sécurité final.
    # ----------------------------------------------------------------
    try:
        output_validation = validate_output(generated_content)
    except Exception as e:
        logger.error(f"Unexpected error in output validation | {e}")
        return PipelineResult(
            success=False,
            error_message="Erreur interne lors de la validation de sortie.",
            prompt_hash=prompt_hash,
            tokens_used=tokens_used,
        )

    if not output_validation.is_valid:
        # [SECURITY] CRITIQUE — log en niveau ERROR pour alerte Grafana immédiate
        # Un output dangereux indique une attaque sophistiquée ou
        # un comportement inattendu du LLM
        logger.error(
            f"DANGEROUS OUTPUT BLOCKED | "
            f"user_id={user_id} | "
            f"prompt_hash={prompt_hash} | "
            f"category={output_validation.category} | "
            f"tokens_wasted={tokens_used}"
        )
        return PipelineResult(
            success=False,
            error_message="Le pipeline généré a été bloqué par les contrôles de sécurité.",
            prompt_hash=prompt_hash,
            tokens_used=tokens_used,
        )

    # ----------------------------------------------------------------
    # SUCCÈS — Toutes les couches ont validé
    #
    # On calcule le temps total de génération pour Grafana.
    # generation_time_ms sera affiché dans le dashboard :
    # "Temps moyen de génération : 1 847ms"
    # ----------------------------------------------------------------
    generation_time_ms = int((time.time() - start_time) * 1000)

    logger.info(
        f"Pipeline generated successfully | "
        f"user_id={user_id} | "
        f"prompt_hash={prompt_hash} | "
        f"tokens={tokens_used} | "
        f"time_ms={generation_time_ms}"
    )

    return PipelineResult(
        success=True,
        pipeline_content=generated_content,
        tokens_used=tokens_used,
        generation_time_ms=generation_time_ms,
        prompt_hash=prompt_hash,
        risk_score=0.0,
    )