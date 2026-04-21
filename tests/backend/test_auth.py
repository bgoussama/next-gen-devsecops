# tests/backend/test_auth.py
#
# Tests pour la Couche 4 — Authentication + RBAC
# Ces tests vérifient que le système de login fonctionne
# et que les permissions sont correctement appliquées.

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.security.auth import (
    authenticate_user,
    create_access_token,
    verify_token,
    has_permission,
    hash_password,
    verify_password,
    UserRole,
    ROLE_PERMISSIONS,
)


class TestPasswordHashing:
    """Vérifie que bcrypt fonctionne correctement."""

    def test_hash_is_different_from_password(self):
        password = "MonMotDePasse123!"
        hashed = hash_password(password)
        assert hashed != password

    def test_verify_correct_password(self):
        password = "MonMotDePasse123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_wrong_password(self):
        hashed = hash_password("MotDePasseCorrect")
        assert verify_password("MotDePasseFaux", hashed) is False

    def test_two_hashes_of_same_password_are_different(self):
        # [SECURITY] bcrypt utilise un sel aléatoire — deux hashes
        # du même mot de passe sont toujours différents
        password = "test123"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2
        # Mais les deux doivent vérifier correctement
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True


class TestAuthentication:
    """Vérifie la logique de login."""

    def test_valid_admin_login(self):
        user = authenticate_user("admin@nextgen.local", "admin123")
        assert user is not None
        assert user["role"] == UserRole.ADMIN

    def test_wrong_password_returns_none(self):
        # [SECURITY] Mauvais mot de passe → None (pas d'exception)
        user = authenticate_user("admin@nextgen.local", "mauvais_mdp")
        assert user is None

    def test_unknown_email_returns_none(self):
        # [SECURITY] Email inconnu → None (pas d'exception)
        # Même comportement que mot de passe faux — User Enumeration Prevention
        user = authenticate_user("inconnu@test.com", "nimporte")
        assert user is None

    def test_developer_login(self):
        user = authenticate_user("dev@nextgen.local", "dev123")
        assert user is not None
        assert user["role"] == UserRole.DEVELOPER


class TestJWT:
    """Vérifie la création et vérification des tokens JWT."""

    def test_create_and_verify_token(self):
        # Créer un token
        token = create_access_token(
            user_id="usr_test",
            email="test@test.com",
            role=UserRole.DEVELOPER,
        )
        assert token is not None
        assert len(token) > 20  # Un JWT est toujours long

        # Vérifier le même token
        token_data = verify_token(token)
        assert token_data is not None
        assert token_data.user_id == "usr_test"
        assert token_data.email == "test@test.com"
        assert token_data.role == UserRole.DEVELOPER

    def test_invalid_token_returns_none(self):
        # [SECURITY] Un token falsifié doit être rejeté
        result = verify_token("token.faux.invalide")
        assert result is None

    def test_tampered_token_returns_none(self):
        # [SECURITY] Modifier le token invalide la signature
        token = create_access_token("usr_1", "test@test.com", UserRole.DEVELOPER)
        # Ajouter un caractère au token
        tampered = token + "X"
        result = verify_token(tampered)
        assert result is None

    def test_token_contains_role(self):
        token = create_access_token("usr_1", "test@test.com", UserRole.ADMIN)
        token_data = verify_token(token)
        assert token_data.role == UserRole.ADMIN


class TestRBAC:
    """Vérifie que les permissions par rôle sont correctes."""

    def test_developer_can_generate(self):
        assert has_permission(UserRole.DEVELOPER, "generate_pipeline") is True

    def test_developer_cannot_deploy_production(self):
        # [SECURITY] Un developer ne peut pas déployer en prod
        assert has_permission(UserRole.DEVELOPER, "deploy_production") is False

    def test_developer_cannot_manage_users(self):
        assert has_permission(UserRole.DEVELOPER, "manage_users") is False

    def test_admin_can_do_everything(self):
        # L'admin a toutes les permissions
        for action in ["generate_pipeline", "deploy_staging",
                       "deploy_production", "manage_users", "admin_infrastructure"]:
            assert has_permission(UserRole.ADMIN, action) is True

    def test_devops_lead_can_deploy_staging(self):
        assert has_permission(UserRole.DEVOPS_LEAD, "deploy_staging") is True

    def test_devops_lead_cannot_deploy_production(self):
        assert has_permission(UserRole.DEVOPS_LEAD, "deploy_production") is False

    def test_architecte_can_deploy_production(self):
        assert has_permission(UserRole.ARCHITECTE, "deploy_production") is True

    def test_architecte_cannot_manage_users(self):
        assert has_permission(UserRole.ARCHITECTE, "manage_users") is False

    def test_unknown_action_returns_false(self):
        # Une action qui n'existe pas → refusée par défaut
        assert has_permission(UserRole.ADMIN, "action_inexistante") is False

    def test_all_roles_can_generate_pipeline(self):
        # Tous les rôles doivent pouvoir générer un pipeline
        for role in UserRole:
            assert has_permission(role, "generate_pipeline") is True