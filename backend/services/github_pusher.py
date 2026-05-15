# backend/services/github_pusher.py
#
# POURQUOI CE FICHIER EXISTE :
#   Après la génération des 4 artefacts, ce module les pousse
#   automatiquement sur GitHub dans une branche dédiée.
#
# POURQUOI GITHUB ET PAS JUSTE RETOURNER LES FICHIERS :
#   1. Persistance : les fichiers survivent au rechargement de la page
#   2. Versioning : chaque génération est tracée dans l'historique Git
#   3. Jenkins : peut lire directement le Jenkinsfile depuis GitHub
#   4. Collaboration : l'équipe peut voir et modifier les fichiers générés
#
# FLUX :
#   artifact_generator.py génère les 4 fichiers
#   → github_pusher.py crée une branche + pousse les fichiers
#   → retourne l'URL de la branche au frontend

import os
import re
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from github import Github, GithubException

logger = logging.getLogger(__name__)


def _fix_terraform_quotes(terraform_content: str) -> str:
    lines = terraform_content.split('\n')
    fixed_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            fixed_lines.append(line)
            continue

        # Remplacer les guillemets simples par des guillemets doubles
        new_line = re.sub(r"'([^']*)'", r'"\1"', line)
        fixed_lines.append(new_line)

    return '\n'.join(fixed_lines)


@dataclass
class PushResult:
    """Résultat du push sur GitHub."""
    success: bool
    branch_name: str = field(default="")
    branch_url: str = field(default="")
    files_pushed: list = field(default_factory=list)
    error_message: str = field(default="")


def push_artifacts_to_github(
    jenkinsfile: str,
    terraform: str,
    dockerfile: str,
    k8s_manifest: str,
    user_id: str = "anonymous",
    prompt_summary: str = "generated",
) -> PushResult:
    """
    Pousse les 4 artefacts sur GitHub dans une branche dédiée.

    [WHY une branche par génération]
    Chaque génération crée sa propre branche nommée :
    pipeline/20260501-143022-usr001

    Avantages :
    - Chaque génération est isolée et traçable
    - Jenkins peut déclencher un pipeline par branche
    - L'utilisateur peut comparer deux générations
    - On peut merger la branche validée dans main

    Args:
        jenkinsfile    : contenu du Jenkinsfile généré
        terraform      : contenu du fichier Terraform
        dockerfile     : contenu du Dockerfile
        k8s_manifest   : contenu du manifest Kubernetes
        user_id        : identifiant de l'utilisateur (pour nommer la branche)
        prompt_summary : résumé court du prompt (pour le message de commit)

    Returns:
        PushResult avec l'URL de la branche créée
    """
    # Lire les variables d'environnement
    github_token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_REPO_NAME", "nextgen-pipelines")
    repo_owner = os.getenv("GITHUB_REPO_OWNER", "bgoussama")

    if not github_token:
        return PushResult(
            success=False,
            error_message="GITHUB_TOKEN manquant dans le fichier .env"
        )

    try:
        # Connexion à GitHub via le token
        # [WHY token et pas username/password]
        # Les tokens sont révocables individuellement et ont des scopes limités.
        # Un token avec scope "repo" ne peut que gérer les repos — pas les paramètres du compte.
        g = Github(github_token)
        repo = g.get_repo(f"{repo_owner}/{repo_name}")

        # Créer un nom de branche unique basé sur la date et l'user_id
        # Format : pipeline/20260501-143022-usr001
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        user_slug = user_id.replace("_", "").replace(" ", "")[:10]
        branch_name = f"pipeline/{timestamp}-{user_slug}"

        # Récupérer le SHA du dernier commit de main
        # [WHY] GitHub a besoin du SHA de la branche parente pour créer une nouvelle branche
        main_branch = repo.get_branch("main")
        main_sha = main_branch.commit.sha

        # Créer la nouvelle branche à partir de main
        repo.create_git_ref(
            ref=f"refs/heads/{branch_name}",
            sha=main_sha,
        )

        logger.info(f"Branch created: {branch_name}")

        # Message de commit — court et descriptif
        # Limité à 100 caractères pour la lisibilité GitHub
        commit_message = f"feat: generate pipeline — {prompt_summary[:80]}"

        # Pousser les 4 fichiers dans la branche
        # create_file() crée le fichier ET fait le commit en une seule opération
        files_pushed = []

        repo.create_file(
            path="Jenkinsfile",
            message=commit_message,
            content=jenkinsfile,
            branch=branch_name,
        )
        files_pushed.append("Jenkinsfile")

        repo.create_file(
            path="terraform/main.tf",
            message=commit_message,
            content=_fix_terraform_quotes(terraform),
            branch=branch_name,
        )
        files_pushed.append("terraform/main.tf")

        repo.create_file(
            path="Dockerfile",
            message=commit_message,
            content=dockerfile,
            branch=branch_name,
        )
        files_pushed.append("Dockerfile")

        repo.create_file(
            path="k8s/manifest.yaml",
            message=commit_message,
            content=k8s_manifest,
            branch=branch_name,
        )
        files_pushed.append("k8s/manifest.yaml")

        # Construire l'URL de la branche
        branch_url = f"https://github.com/{repo_owner}/{repo_name}/tree/{branch_name}"

        logger.info(
            f"Push success | branch={branch_name} | "
            f"files={files_pushed} | user={user_id}"
        )

        return PushResult(
            success=True,
            branch_name=branch_name,
            branch_url=branch_url,
            files_pushed=files_pushed,
        )

    except GithubException as e:
        logger.error(f"GitHub API error: {e.status} — {e.data}")
        return PushResult(
            success=False,
            error_message=f"Erreur GitHub: {e.data.get('message', str(e))}"
        )
    except Exception as e:
        logger.error(f"Unexpected error in github_pusher: {e}")
        return PushResult(
            success=False,
            error_message=f"Erreur inattendue: {str(e)}"
        )