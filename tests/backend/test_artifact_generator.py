# tests/backend/test_artifact_generator.py
import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")))

from backend.services.artifact_generator import (
    generate_all_artifacts,
    _clean_json_response,
    ArtifactResult,
)

# Réponse JSON valide simulée
VALID_JSON_RESPONSE = '''{
  "jenkinsfile": "pipeline { agent any stages { stage('Build') { steps { sh 'npm install' } } } }",
  "terraform": "provider \\"aws\\" { region = \\"eu-west-3\\" }",
  "dockerfile": "FROM node:18-alpine\\nRUN adduser -D appuser\\nUSER appuser",
  "k8s_manifest": "apiVersion: apps/v1\\nkind: Deployment\\nmetadata:\\n  name: app"
}'''


def make_mock_groq_response(content: str, tokens: int = 800):
    mock = MagicMock()
    mock.choices[0].message.content = content
    mock.usage.total_tokens = tokens
    return mock


class TestCleanJsonResponse:
    """Teste le nettoyage des réponses LLM."""

    def test_removes_json_markdown(self):
        raw = "```json\n{\"key\": \"value\"}\n```"
        result = _clean_json_response(raw)
        assert result == '{"key": "value"}'

    def test_removes_plain_markdown(self):
        raw = "```\n{\"key\": \"value\"}\n```"
        result = _clean_json_response(raw)
        assert result == '{"key": "value"}'

    def test_keeps_clean_json(self):
        raw = '{"key": "value"}'
        result = _clean_json_response(raw)
        assert result == '{"key": "value"}'


class TestGenerateAllArtifacts:

    def test_success_returns_4_artifacts(self):
        """Vérifie que les 4 artefacts sont retournés."""
        with patch("backend.services.artifact_generator.Groq") as MockGroq:
            mock_client = MockGroq.return_value
            mock_client.chat.completions.create.return_value = \
                make_mock_groq_response(VALID_JSON_RESPONSE)

            with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test"}):
                result = generate_all_artifacts("Deploy a Node.js app")

        assert result.success is True
        assert "pipeline" in result.jenkinsfile
        assert "provider" in result.terraform
        assert "FROM" in result.dockerfile
        assert "apiVersion" in result.k8s_manifest
        assert result.tokens_used == 800

    def test_missing_api_key(self):
        """Vérifie l'erreur si clé Groq manquante."""
        env_without_key = {
            k: v for k, v in os.environ.items()
            if k != "GROQ_API_KEY"
        }
        with patch.dict(os.environ, env_without_key, clear=True):
            result = generate_all_artifacts("Deploy app")

        assert result.success is False
        assert "GROQ_API_KEY" in result.error_message

    def test_invalid_json_retries(self):
        """Vérifie le retry si le LLM retourne du JSON invalide."""
        from groq import RateLimitError

        with patch("backend.services.artifact_generator.Groq") as MockGroq:
            mock_client = MockGroq.return_value
            mock_client.chat.completions.create.side_effect = [
                make_mock_groq_response("not valid json"),
                make_mock_groq_response("still not json"),
                make_mock_groq_response(VALID_JSON_RESPONSE),
            ]

            with patch("backend.services.artifact_generator.time.sleep"):
                with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test"}):
                    result = generate_all_artifacts("Deploy app")

        assert result.success is True
        assert result.attempts == 3

    def test_legitimate_prompt_accepted(self):
        """Un prompt légitime doit générer des artefacts."""
        with patch("backend.services.artifact_generator.Groq") as MockGroq:
            mock_client = MockGroq.return_value
            mock_client.chat.completions.create.return_value = \
                make_mock_groq_response(VALID_JSON_RESPONSE)

            with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test"}):
                result = generate_all_artifacts(
                    "Deploy a Python FastAPI with PostgreSQL on AWS EC2"
                )

        assert result.success is True