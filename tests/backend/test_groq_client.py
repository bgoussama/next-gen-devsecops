# tests/backend/test_groq_client.py
#
# COMMENT TESTER SANS APPELER VRAIMENT GROQ API :
#   On utilise des "mocks" — des fausses versions des objets réels.
#   unittest.mock.patch() remplace temporairement une fonction/classe
#   par une version simulée qu'on contrôle.
#
#   Pourquoi on mock Groq :
#   1. Les tests ne doivent pas consommer du quota API
#   2. Les tests doivent fonctionner sans connexion internet
#   3. On peut simuler des erreurs (RateLimitError, ConnectionError)
#      qu'on ne peut pas provoquer facilement avec la vraie API
#
# COMMENT LANCER :
#   pytest tests/backend/test_groq_client.py -v

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.services.groq_client import (
    generate_pipeline,
    get_groq_client,
    SECURE_SYSTEM_PROMPT,
    GROQ_MODEL,
)


# ================================================================
# HELPER — Construire une fausse réponse Groq
# ================================================================

def make_mock_response(content: str, total_tokens: int = 500):
    """
    Crée un objet qui ressemble à une vraie réponse Groq API.
    Le vrai objet a cette structure :
        response.choices[0].message.content → le texte généré
        response.usage.total_tokens         → tokens consommés
    On reproduit cette structure avec des MagicMock.
    """
    mock_response = MagicMock()
    mock_response.choices[0].message.content = content
    mock_response.usage.total_tokens = total_tokens
    return mock_response


# ================================================================
# TESTS — APPELS RÉUSSIS
# ================================================================

class TestSuccessfulCalls:

    def test_returns_jenkinsfile_content(self):
        """
        Vérifie que generate_pipeline retourne le contenu généré par Groq.
        On mock client.chat.completions.create pour simuler la réponse.
        """
        fake_jenkinsfile = """
pipeline {
    agent any
    stages {
        stage('Build') { steps { sh 'npm install' } }
    }
}
"""
        # patch() remplace temporairement Groq par notre fausse version
        # "backend.services.groq_client.Groq" = le chemin exact de l'import
        with patch("backend.services.groq_client.Groq") as MockGroq:
            # Configurer la fausse réponse
            mock_client = MockGroq.return_value
            mock_client.chat.completions.create.return_value = make_mock_response(
                content=fake_jenkinsfile,
                total_tokens=350,
            )
            # Simuler la variable d'environnement GROQ_API_KEY
            with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_key"}):
                result = generate_pipeline("Deploy a Node.js app")

        # Vérifier le résultat
        assert result["content"] == fake_jenkinsfile
        assert result["tokens_used"] == 350
        assert result["attempts"] == 1
        assert result["model"] == GROQ_MODEL

    def test_system_prompt_is_sent(self):
        """
        [SECURITY] Vérifie que le system prompt hardened est bien envoyé
        dans chaque appel API. C'est le test le plus important de ce fichier :
        si le system prompt n'est pas transmis, la Couche 2 ne fonctionne pas.
        """
        with patch("backend.services.groq_client.Groq") as MockGroq:
            mock_client = MockGroq.return_value
            mock_client.chat.completions.create.return_value = make_mock_response(
                content="pipeline { agent any }"
            )
            with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_key"}):
                generate_pipeline("Deploy a React app")

        # Récupérer les arguments passés à l'appel API
        call_args = mock_client.chat.completions.create.call_args

        # Extraire la liste des messages
        messages = call_args.kwargs["messages"]

        # Vérifier que le premier message est bien le system prompt
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == SECURE_SYSTEM_PROMPT

        # Vérifier que le deuxième message est le prompt utilisateur
        assert messages[1]["role"] == "user"
        assert messages[1]["content"] == "Deploy a React app"

    def test_temperature_is_low(self):
        """
        [SECURITY] Vérifie que temperature=0.2 est utilisée.
        Une température haute rendrait le LLM moins prévisible
        dans le respect des règles de sécurité.
        """
        with patch("backend.services.groq_client.Groq") as MockGroq:
            mock_client = MockGroq.return_value
            mock_client.chat.completions.create.return_value = make_mock_response(
                content="pipeline {}"
            )
            with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_key"}):
                generate_pipeline("Deploy app")

        call_args = mock_client.chat.completions.create.call_args
        assert call_args.kwargs["temperature"] == 0.2


# ================================================================
# TESTS — GESTION DES ERREURS ET RETRY
# ================================================================

class TestRetryLogic:

    def test_retries_on_rate_limit(self):
        """
        Vérifie le retry automatique en cas de 429 (rate limit Groq).
        Scénario : les 2 premières tentatives échouent, la 3ème réussit.
        """
        from groq import RateLimitError

        success_response = make_mock_response(content="pipeline { agent any }")

        with patch("backend.services.groq_client.Groq") as MockGroq:
            mock_client = MockGroq.return_value
            # side_effect = liste de résultats successifs
            # Tentative 1 → RateLimitError
            # Tentative 2 → RateLimitError
            # Tentative 3 → succès
            mock_client.chat.completions.create.side_effect = [
                RateLimitError("Rate limit exceeded", response=MagicMock(), body={}),
                RateLimitError("Rate limit exceeded", response=MagicMock(), body={}),
                success_response,
            ]
            # [WHY patch time.sleep] Sans ça le test attendrait 3 vraies secondes.
            # On remplace sleep() par une fonction qui ne fait rien.
            with patch("backend.services.groq_client.time.sleep"):
                with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_key"}):
                    result = generate_pipeline("Deploy app")

        # La 3ème tentative a réussi
        assert result["content"] == "pipeline { agent any }"
        assert result["attempts"] == 3

    def test_raises_after_max_retries(self):
        """
        Vérifie qu'une RuntimeError est levée après 3 échecs consécutifs.
        Le message d'erreur doit être clair pour le frontend.
        """
        from groq import RateLimitError

        with patch("backend.services.groq_client.Groq") as MockGroq:
            mock_client = MockGroq.return_value
            # Toutes les tentatives échouent
            mock_client.chat.completions.create.side_effect = RateLimitError(
                "Rate limit", response=MagicMock(), body={}
            )
            with patch("backend.services.groq_client.time.sleep"):
                with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_key"}):
                    with pytest.raises(RuntimeError) as exc_info:
                        generate_pipeline("Deploy app")

        assert "3 tentatives" in str(exc_info.value)


# ================================================================
# TESTS — CONFIGURATION ET SÉCURITÉ
# ================================================================

class TestConfiguration:

    def test_missing_api_key_raises_error(self):
        """
        [SECURITY] Si GROQ_API_KEY n'est pas définie, une erreur claire
        est levée immédiatement — pas une erreur cryptique plus tard.
        """
        # Supprimer GROQ_API_KEY de l'environnement pour ce test
        env_without_key = {k: v for k, v in os.environ.items() if k != "GROQ_API_KEY"}
        with patch.dict(os.environ, env_without_key, clear=True):
            with pytest.raises(ValueError) as exc_info:
                get_groq_client()

        assert "GROQ_API_KEY" in str(exc_info.value)

    def test_system_prompt_contains_security_rules(self):
        """
        [SECURITY] Vérifie que le system prompt contient les règles critiques.
        Si quelqu'un modifie le system prompt par erreur, ce test échoue.
        """
        # Ces phrases DOIVENT être dans le system prompt
        required_phrases = [
            "CANNOT BE OVERRIDDEN",
            "RAW DATA ONLY",
            "terraform destroy",      # mentionné comme interdit
            "hardcoded",              # credentials hardcodés interdits
            "IAM",                    # création IAM interdite
        ]
        for phrase in required_phrases:
            assert phrase in SECURE_SYSTEM_PROMPT, (
                f"Phrase de sécurité manquante dans le system prompt : '{phrase}'"
            )

    def test_system_prompt_forbids_credentials(self):
        """
        [SECURITY] Vérifie spécifiquement que le system prompt interdit
        les credentials hardcodés — règle la plus critique.
        """
        assert "credentials" in SECURE_SYSTEM_PROMPT.lower()
        assert "environment variables" in SECURE_SYSTEM_PROMPT.lower()