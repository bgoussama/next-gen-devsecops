# tests/backend/test_github_pusher.py
import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")))

from backend.services.github_pusher import push_artifacts_to_github

FAKE_ARTIFACTS = {
    "jenkinsfile": "pipeline { agent any }",
    "terraform": 'resource "aws_instance" "app" {}',
    "dockerfile": "FROM node:18-alpine\nUSER node",
    "k8s_manifest": "apiVersion: apps/v1\nkind: Deployment",
}


class TestPushArtifacts:

    def test_missing_token_returns_error(self):
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
        with patch.dict(os.environ, env, clear=True):
            result = push_artifacts_to_github(**FAKE_ARTIFACTS)
        assert result.success is False
        assert "GITHUB_TOKEN" in result.error_message

    def test_success_returns_branch_url(self):
        with patch("backend.services.github_pusher.Github") as MockGithub:
            mock_repo = MagicMock()
            mock_branch = MagicMock()
            mock_branch.commit.sha = "abc123"
            mock_repo.get_branch.return_value = mock_branch
            MockGithub.return_value.get_repo.return_value = mock_repo

            with patch.dict(os.environ, {
                "GITHUB_TOKEN": "ghp_test",
                "GITHUB_REPO_OWNER": "bgoussama",
                "GITHUB_REPO_NAME": "nextgen-pipelines",
            }):
                result = push_artifacts_to_github(
                    **FAKE_ARTIFACTS,
                    user_id="usr_001",
                )

        assert result.success is True
        assert "github.com" in result.branch_url
        assert "pipeline/" in result.branch_name
        assert len(result.files_pushed) == 4

    def test_branch_name_contains_user_id(self):
        with patch("backend.services.github_pusher.Github") as MockGithub:
            mock_repo = MagicMock()
            mock_branch = MagicMock()
            mock_branch.commit.sha = "abc123"
            mock_repo.get_branch.return_value = mock_branch
            MockGithub.return_value.get_repo.return_value = mock_repo

            with patch.dict(os.environ, {
                "GITHUB_TOKEN": "ghp_test",
                "GITHUB_REPO_OWNER": "bgoussama",
                "GITHUB_REPO_NAME": "nextgen-pipelines",
            }):
                result = push_artifacts_to_github(
                    **FAKE_ARTIFACTS,
                    user_id="usr_001",
                )

        assert "usr001" in result.branch_name

    def test_github_exception_returns_error(self):
        from github import GithubException
        with patch("backend.services.github_pusher.Github") as MockGithub:
            MockGithub.return_value.get_repo.side_effect = GithubException(
                404, {"message": "Not Found"}, None
            )
            with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_test"}):
                result = push_artifacts_to_github(**FAKE_ARTIFACTS)

        assert result.success is False
        assert "GitHub" in result.error_message