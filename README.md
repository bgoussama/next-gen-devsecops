# Next-Gen DevSecOps Platform

> Plateforme d'automatisation DevSecOps pilotée par l'IA : de la description en langage naturel
> au déploiement sécurisé sur AWS EC2 via un pipeline CI/CD intégral.

![Stack](https://img.shields.io/badge/stack-Python%20%7C%20React%20%7C%20Jenkins-blue)
![Security](https://img.shields.io/badge/security-6%20couches%20Defense--in--Depth-red)
![LLM](https://img.shields.io/badge/LLM-Groq%20API-orange)
![IaC](https://img.shields.io/badge/IaC-Terraform%20%7C%20AWS-yellow)

---

## Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Architecture](#architecture)
- [Structure du projet](#structure-du-projet)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Variables d'environnement](#variables-denvironnement)
- [Utilisation](#utilisation)
- [Sécurité](#sécurité)
- [Tests](#tests)
- [Contribuer](#contribuer)

---

## Vue d'ensemble

Next-Gen DevSecOps résout le problème de la complexité des pipelines CI/CD modernes.
Un utilisateur saisit une description en langage naturel ("Déploie une API Node.js avec MongoDB
sur AWS"), et la plateforme génère automatiquement :

- Un **Jenkinsfile** complet avec stages de sécurité intégrés
- Une **configuration Terraform** pour provisionner l'infrastructure AWS
- Des **scripts Bash** d'auto-configuration

Le tout est versionné sur GitHub, scanné par SonarQube, conteneurisé via Docker, et déployé
sur AWS EC2 — sans intervention manuelle.

---

## Architecture

```
Utilisateur (langage naturel)
        |
        v
[React Frontend] ──────────────────────────────────────────────────────────────
        |                                                                       |
        | HTTP POST /generate                                           Historique
        v                                                               pipelines
[Backend Orchestrateur — Python/FastAPI]
        |
        |── Couche 1 : Input Validation (regex + LLM Guard)
        |── Couche 2 : System Prompt Hardening
        |
        v
[Groq API — LLM Llama-3]
        |
        |── Couche 3 : Output Validation
        |── Couche 4 : RBAC + Rate Limiting
        |
        v
[GitHub — push automatique du Jenkinsfile + Terraform]
        |
        v
[Jenkins — pipeline déclenché par webhook]
        |
        |── SonarQube (SAST — analyse statique)
        |── Docker build + push
        |── Couche 5 : Terraform apply + Guardrails + AWS SCP
        |── Kubernetes deploy
        |
        v
[AWS EC2 — Infrastructure provisionnée]
        |
        v
[Prometheus + Grafana — Monitoring temps réel]
        |
        └── Couche 6 : Audit logs + alertes de sécurité
```

---

## Structure du projet

```
next-gen-devsecops/
│
├── backend/                        # Orchestrateur principal (Python / FastAPI)
│   ├── security/                   # Modules de sécurité des prompts (6 couches)
│   │   ├── prompt_guard.py         # Couche 1 : validation regex + LLM Guard
│   │   ├── output_validator.py     # Couche 3 : validation de la réponse LLM
│   │   └── audit_logger.py         # Couche 6 : logs d'audit structurés
│   ├── api/
│   │   ├── routes.py               # Endpoints FastAPI (/generate, /health, /history)
│   │   └── middleware.py           # Couche 4 : RBAC + rate limiting
│   ├── services/
│   │   ├── groq_client.py          # Couche 2 : appel Groq API avec system prompt hardened
│   │   └── pipeline_generator.py   # Orchestration complète du flux de génération
│   ├── utils/
│   │   └── helpers.py              # Fonctions utilitaires pures
│   ├── config/
│   │   └── rate_limits.yaml        # Config rate limiting par rôle
│   └── main.py                     # Point d'entrée de l'application FastAPI
│
├── frontend/                       # Interface utilisateur (React.js)
│   └── src/
│       ├── components/             # Composants réutilisables (Editor, Validator, etc.)
│       ├── pages/                  # Pages principales (Home, History, Dashboard)
│       ├── hooks/                  # Custom hooks (useGenerate, useAuth)
│       ├── services/               # Appels API vers le backend
│       └── utils/                  # Helpers frontend (formatters, constants)
│
├── jenkins/
│   └── templates/                  # Templates Jenkinsfiles générés par l'IA
│       └── Jenkinsfile.base        # Template de base avec stages de sécurité
│
├── terraform/
│   ├── modules/
│   │   ├── ec2/                    # Module Terraform pour instances EC2
│   │   ├── networking/             # VPC, subnets, security groups
│   │   └── security/               # IAM policies, KMS, CloudTrail
│   ├── guardrails/
│   │   └── terraform_guard.py      # Couche 5 : analyse plan avant apply
│   └── environments/
│       ├── staging/                # Variables Terraform pour staging
│       └── prod/                   # Variables Terraform pour production
│
├── monitoring/
│   ├── prometheus/
│   │   └── prometheus.yml          # Config scraping + règles d'alerte
│   ├── grafana/
│   │   └── dashboards/             # Dashboards JSON importables
│   └── alertmanager/
│       └── alertmanager.yml        # Routing des alertes (email, Slack, PagerDuty)
│
├── docs/
│   ├── architecture/               # Schémas et décisions d'architecture (ADR)
│   ├── security/                   # Threat model, politique de sécurité
│   └── api/                        # Documentation des endpoints
│
├── tests/
│   ├── backend/                    # Tests unitaires Python (pytest)
│   ├── frontend/                   # Tests React (Jest + Testing Library)
│   └── integration/                # Tests end-to-end du pipeline complet
│
├── .github/
│   └── workflows/
│       └── ci.yml                  # Pipeline GitHub Actions (lint + tests)
│
├── .gitignore                      # Exclusions (secrets, node_modules, .terraform, etc.)
├── .env.example                    # Template des variables d'environnement
├── docker-compose.yml              # Stack locale complète pour le développement
└── README.md                       # Ce fichier
```

---

## Prérequis

- Python >= 3.11
- Node.js >= 20 (pour le frontend)
- Docker + Docker Compose
- Terraform >= 1.5
- Un compte AWS avec les droits EC2, VPC, S3
- Une clé API Groq (https://console.groq.com)

---

## Installation

```bash
# 1. Cloner le repo
git clone https://github.com/oussama-bagy/next-gen-devsecops.git
cd next-gen-devsecops

# 2. Copier et remplir les variables d'environnement
cp .env.example .env
# Éditer .env avec vos valeurs réelles

# 3. Lancer la stack complète en local (backend + monitoring)
docker-compose up -d

# 4. Installer les dépendances backend séparément si besoin
cd backend
pip install -r requirements.txt

# 5. Installer les dépendances frontend
cd ../frontend
npm install
npm run dev
```

---

## Variables d'environnement

| Variable              | Description                            | Exemple                    |
|-----------------------|----------------------------------------|----------------------------|
| `GROQ_API_KEY`        | Clé API Groq pour l'inférence LLM      | `gsk_...`                  |
| `GITHUB_TOKEN`        | Token GitHub pour le push automatique  | `ghp_...`                  |
| `GITHUB_REPO`         | Repo cible pour les fichiers générés   | `oussama-bagy/pipelines`   |
| `AWS_REGION`          | Région AWS cible                       | `eu-west-3`                |
| `SECRET_KEY`          | Clé de signature JWT                   | `changeme-en-prod`         |
| `REDIS_URL`           | URL Redis pour le rate limiting        | `redis://localhost:6379`   |
| `SONARQUBE_TOKEN`     | Token SonarQube pour les scans SAST    | `squ_...`                  |
| `PROMETHEUS_PORT`     | Port d'exposition des métriques        | `9090`                     |

Ne jamais committer le fichier `.env` réel. Seul `.env.example` doit être versionné.

---

## Utilisation

```bash
# Lancer le backend en mode développement
cd backend
uvicorn main:app --reload --port 8000

# L'API est disponible sur http://localhost:8000
# Documentation Swagger : http://localhost:8000/docs

# Lancer le frontend
cd frontend
npm run dev
# Interface disponible sur http://localhost:3000
```

---

## Sécurité

La plateforme implémente une architecture **Defense-in-Depth** en 6 couches :

| Couche | Module                  | Description                                              |
|--------|-------------------------|----------------------------------------------------------|
| 1      | `prompt_guard.py`       | Filtrage regex + détection sémantique (LLM Guard)        |
| 2      | `groq_client.py`        | System prompt hardened — règles non-overridables         |
| 3      | `output_validator.py`   | Scan de la réponse LLM avant transmission à Jenkins      |
| 4      | `middleware.py`         | RBAC par rôle + rate limiting par user/IP/global         |
| 5      | `terraform_guard.py`    | Analyse du plan Terraform + AWS Service Control Policies |
| 6      | `audit_logger.py`       | Logs d'audit complets + alertes Grafana temps réel       |

Référence : OWASP LLM Top 10 — LLM01:2025 Prompt Injection

---

## Tests

```bash
# Tests unitaires backend
cd tests/backend
pytest -v --cov=backend

# Tests frontend
cd tests/frontend
npm test

# Rapport de couverture
pytest --cov=backend --cov-report=html
```

---

## Contribuer

Voir [CONTRIBUTING.md](./CONTRIBUTING.md) pour les conventions de branches et de commits.

---

*Projet Fin de Semestre — ENSA Marrakech 2026 | Bagy Oussama | Cybersécurité & Télécommunications*
