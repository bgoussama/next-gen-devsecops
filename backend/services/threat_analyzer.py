"""
Analyse MITRE ATT&CK des artefacts DevSecOps generes.

Le module reste volontairement deterministe : il inspecte le contenu brut des
Jenkinsfile, Terraform, Dockerfile et manifests Kubernetes sans appel externe.
"""

import re
from dataclasses import dataclass, field


@dataclass
class ThreatAnalysisResult:
    score: int
    risk_level: str
    techniques: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    summary: str = ""


def _normalize(content: str | None) -> str:
    """Normalise un artefact pour faciliter les recherches regex."""
    return content or ""


def _has_hardcoded_credentials(*artifacts: str) -> tuple[bool, str]:
    """Detecte les secrets codifies en dur dans les artefacts."""
    combined = "\n".join(artifacts)
    patterns = [
        r"(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]",
        r"(?i)aws_access_key_id\s*=\s*['\"]?AKIA[0-9A-Z]{16}['\"]?",
        r"(?i)aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{30,}['\"]?",
    ]

    for pattern in patterns:
        match = re.search(pattern, combined)
        if match:
            return True, match.group(0)[:120]
    return False, ""


def _uses_secret_management(*artifacts: str) -> tuple[bool, str]:
    """Repere l'usage de variables d'environnement ou de gestionnaires de secrets."""
    combined = "\n".join(artifacts)
    patterns = [
        r"(?i)environment\s*\{",
        r"(?im)^ENV\s+[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY)[A-Z0-9_]*",
        r"\$\{?[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY)[A-Z0-9_]*\}?",
        r"(?i)(aws_secretsmanager|secretsmanager|vault|sops|sealedsecret|secretKeyRef|envFrom|withCredentials|credentialsId)",
        r"(?i)kubernetes_secret|data\.aws_secretsmanager_secret",
    ]
    for pattern in patterns:
        match = re.search(pattern, combined)
        if match:
            return True, match.group(0)[:120]
    return False, ""


def _has_unrestricted_public_ports(terraform: str, k8s_manifest: str) -> tuple[bool, str]:
    """Detecte une exposition publique trop large des ports."""
    combined = f"{terraform}\n{k8s_manifest}"
    risky_patterns = [
        r"cidr_blocks\s*=\s*\[[^\]]*0\.0\.0\.0/0[^\]]*\]",
        r"ipv6_cidr_blocks\s*=\s*\[[^\]]*::/0[^\]]*\]",
        r"loadBalancerSourceRanges\s*:\s*\[[^\]]*0\.0\.0\.0/0[^\]]*\]",
    ]
    has_public_cidr = any(re.search(pattern, combined, re.DOTALL) for pattern in risky_patterns)
    has_open_all_ports = re.search(r"from_port\s*=\s*0[\s\S]{0,120}to_port\s*=\s*(0|65535)", terraform)
    has_all_protocols = re.search(r"protocol\s*=\s*['\"]-1['\"]", terraform)

    if has_public_cidr and (has_open_all_ports or has_all_protocols):
        evidence = "0.0.0.0/0 avec tous les ports ou tous les protocoles"
        return True, evidence
    return False, ""


def _has_restrictive_security_groups(terraform: str) -> tuple[bool, str]:
    """Repere des security groups avec CIDR limites."""
    if "aws_security_group" not in terraform:
        return False, ""

    if re.search(r"cidr_blocks\s*=\s*\[[^\]]*(10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|/32)[^\]]*\]", terraform):
        return True, "Security group avec CIDR prive ou /32"

    if "0.0.0.0/0" not in terraform:
        return True, "Security group sans exposition 0.0.0.0/0"

    return False, ""


def _docker_image_risk(dockerfile: str, k8s_manifest: str) -> tuple[bool, str]:
    """Detecte les images latest ou sans version explicite."""
    combined = f"{dockerfile}\n{k8s_manifest}"
    from_without_tag = re.search(r"(?im)^FROM\s+[^\s:@]+(?:\s|$)", dockerfile)
    latest_tag = re.search(r"(?im)(^FROM\s+\S+:latest\b|image:\s*\S+:latest\b)", combined)
    image_without_tag = re.search(r"(?im)image:\s*[^\s:@]+(?:\s|$)", k8s_manifest)

    if latest_tag:
        return True, latest_tag.group(0)[:120]
    if from_without_tag or image_without_tag:
        return True, "Image sans tag versionne explicite"
    return False, ""


def _docker_has_specific_version_and_non_root(dockerfile: str) -> tuple[bool, str]:
    """Verifie un tag Docker versionne et un utilisateur non-root."""
    has_specific_from = bool(re.search(r"(?im)^FROM\s+\S+:[^\s:]+", dockerfile)) and ":latest" not in dockerfile.lower()
    has_non_root_user = bool(re.search(r"(?im)^USER\s+(?!root\b|0\b).+", dockerfile))

    if has_specific_from and has_non_root_user:
        return True, "Image versionnee et directive USER non-root"
    return False, ""


def _has_dependency_scan(jenkinsfile: str) -> tuple[bool, str]:
    """Repere Trivy ou un outil equivalent dans le pipeline."""
    tools = ["trivy", "snyk", "dependency-check", "grype", "safety", "npm audit", "pip-audit"]
    lower = jenkinsfile.lower()
    for tool in tools:
        if tool in lower:
            return True, tool
    return False, ""


def _has_iam_admin_risk(terraform: str) -> tuple[bool, str]:
    """Detecte la creation de comptes IAM ou de privileges administrateur."""
    risky_patterns = [
        r"aws_iam_user",
        r"AdministratorAccess",
        r"Action\s*=\s*['\"]\*['\"]",
        r"Action\s*=\s*\[[^\]]*['\"]\*['\"]",
        r"iam:\*",
    ]
    for pattern in risky_patterns:
        match = re.search(pattern, terraform, re.IGNORECASE | re.DOTALL)
        if match:
            return True, match.group(0)[:120]
    return False, ""


def _risk_level(score: int) -> str:
    """Convertit le score numerique en niveau de risque."""
    if score >= 80:
        return "LOW"
    if score >= 60:
        return "MEDIUM"
    if score >= 40:
        return "HIGH"
    return "CRITICAL"


def analyze_threats(
    jenkinsfile: str = "",
    terraform: str = "",
    dockerfile: str = "",
    k8s_manifest: str = "",
) -> ThreatAnalysisResult:
    """
    Analyse les artefacts et retourne le score MITRE ATT&CK.

    Le score commence a 100 et perd 20 points par technique AT_RISK.
    """
    jenkinsfile = _normalize(jenkinsfile)
    terraform = _normalize(terraform)
    dockerfile = _normalize(dockerfile)
    k8s_manifest = _normalize(k8s_manifest)

    techniques = []
    recommendations = []

    hardcoded, hardcoded_evidence = _has_hardcoded_credentials(jenkinsfile, terraform, dockerfile, k8s_manifest)
    secret_mgmt, secret_evidence = _uses_secret_management(jenkinsfile, terraform, dockerfile, k8s_manifest)
    if hardcoded:
        techniques.append({
            "id": "T1552",
            "name": "Unsecured Credentials",
            "status": "AT_RISK",
            "description": "Des credentials semblent codifies en dur dans les artefacts.",
            "evidence": hardcoded_evidence,
        })
        recommendations.append("Remplacer les credentials codifies en dur par des variables d'environnement, Vault, AWS Secrets Manager ou des secrets Kubernetes.")
    elif secret_mgmt:
        techniques.append({
            "id": "T1552",
            "name": "Unsecured Credentials",
            "status": "PROTECTED",
            "description": "Les secrets semblent externalises via variables ou gestionnaire de secrets.",
            "evidence": secret_evidence,
        })
    else:
        techniques.append({
            "id": "T1552",
            "name": "Unsecured Credentials",
            "status": "UNKNOWN",
            "description": "Aucun secret ni mecanisme de gestion des secrets clairement detecte.",
            "evidence": "Aucun indice exploitable",
        })
        recommendations.append("Documenter explicitement la gestion des secrets dans Jenkins, Terraform ou Kubernetes.")

    public_ports, public_evidence = _has_unrestricted_public_ports(terraform, k8s_manifest)
    restrictive_sg, sg_evidence = _has_restrictive_security_groups(terraform)
    if public_ports:
        techniques.append({
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "status": "AT_RISK",
            "description": "Des ports sont exposes publiquement sans restriction suffisante.",
            "evidence": public_evidence,
        })
        recommendations.append("Limiter les security groups aux CIDR necessaires et eviter 0.0.0.0/0 sur tous les ports.")
    elif restrictive_sg:
        techniques.append({
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "status": "PROTECTED",
            "description": "Les security groups Terraform semblent restrictifs.",
            "evidence": sg_evidence,
        })
    else:
        techniques.append({
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "status": "UNKNOWN",
            "description": "Aucune exposition publique critique ni security group restrictif clairement detecte.",
            "evidence": "Configuration reseau insuffisante pour conclure",
        })
        recommendations.append("Ajouter des security groups Terraform explicites avec des CIDR restrictifs.")

    image_risk, image_risk_evidence = _docker_image_risk(dockerfile, k8s_manifest)
    image_protected, image_protected_evidence = _docker_has_specific_version_and_non_root(dockerfile)
    if image_risk:
        techniques.append({
            "id": "T1525",
            "name": "Implant Container Image",
            "status": "AT_RISK",
            "description": "Une image Docker utilise latest ou ne declare pas de version explicite.",
            "evidence": image_risk_evidence,
        })
        recommendations.append("Utiliser des tags d'image immuables, signer les images et executer le conteneur avec un utilisateur non-root.")
    elif image_protected:
        techniques.append({
            "id": "T1525",
            "name": "Implant Container Image",
            "status": "PROTECTED",
            "description": "Le Dockerfile utilise une version explicite et un utilisateur non-root.",
            "evidence": image_protected_evidence,
        })
    else:
        techniques.append({
            "id": "T1525",
            "name": "Implant Container Image",
            "status": "UNKNOWN",
            "description": "La posture image conteneur n'est pas suffisante pour conclure.",
            "evidence": "Tag versionne ou utilisateur non-root manquant",
        })
        recommendations.append("Ajouter un tag d'image specifique et une directive USER non-root dans le Dockerfile.")

    dependency_scan, scan_evidence = _has_dependency_scan(jenkinsfile)
    if dependency_scan:
        techniques.append({
            "id": "T1195",
            "name": "Supply Chain Compromise",
            "status": "PROTECTED",
            "description": "Le pipeline contient un scan de dependances ou d'image.",
            "evidence": scan_evidence,
        })
    else:
        techniques.append({
            "id": "T1195",
            "name": "Supply Chain Compromise",
            "status": "AT_RISK",
            "description": "Aucun scan de dependances ou d'image n'a ete detecte dans le Jenkinsfile.",
            "evidence": "Trivy, Snyk, Dependency-Check ou equivalent absent",
        })
        recommendations.append("Ajouter un stage Jenkins de scan avec Trivy, Snyk, OWASP Dependency-Check ou Grype.")

    iam_risk, iam_evidence = _has_iam_admin_risk(terraform)
    if iam_risk:
        techniques.append({
            "id": "T1078",
            "name": "Valid Accounts",
            "status": "AT_RISK",
            "description": "Terraform cree des utilisateurs IAM ou des privileges administrateur.",
            "evidence": iam_evidence,
        })
        recommendations.append("Eviter les aws_iam_user permanents et remplacer les droits admin par des roles IAM a moindre privilege.")
    else:
        techniques.append({
            "id": "T1078",
            "name": "Valid Accounts",
            "status": "PROTECTED",
            "description": "Aucune creation d'utilisateur IAM ni acces administrateur detecte.",
            "evidence": "aws_iam_user et privileges admin absents",
        })

    at_risk_count = sum(1 for technique in techniques if technique["status"] == "AT_RISK")
    score = max(0, 100 - (20 * at_risk_count))
    risk_level = _risk_level(score)
    protected_count = sum(1 for technique in techniques if technique["status"] == "PROTECTED")

    summary = (
        f"Analyse MITRE ATT&CK terminee : {protected_count} techniques protegees, "
        f"{at_risk_count} a risque, score {score}/100 ({risk_level})."
    )

    return ThreatAnalysisResult(
        score=score,
        risk_level=risk_level,
        techniques=techniques,
        recommendations=recommendations,
        summary=summary,
    )
