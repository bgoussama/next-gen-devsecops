"""
Terraform Guard — Couche 5 Sécurité
Analyse le code Terraform AVANT exécution et bloque les ressources dangereuses/coûteuses.
"""

import re
from dataclasses import dataclass, field

# Ressources totalement interdites
FORBIDDEN_RESOURCES = {
    "aws_iam_user": "Création d'utilisateurs IAM interdite (risque sécurité)",
    "aws_iam_access_key": "Création de clés d'accès IAM interdite (risque fuite credentials)",
    "aws_db_instance": "RDS interdit (coûteux — min ~$15/mois)",
    "aws_elasticsearch_domain": "Elasticsearch interdit (coûteux — min ~$25/mois)",
    "aws_redshift_cluster": "Redshift interdit (coûteux — min ~$180/mois)",
}

# Seuls types d'instance EC2 autorisés (Free Tier)
ALLOWED_INSTANCE_TYPES = {"t3.micro", "t2.micro"}

# Coûts mensuels estimés par ressource (en USD)
RESOURCE_COSTS = {
    "aws_instance": 0.0,          # t3.micro Free Tier
    "aws_security_group": 0.0,
    "aws_s3_bucket": 0.0,         # Free Tier 5GB
    "aws_cloudwatch_metric_alarm": 0.0,
    "aws_db_instance": 15.0,
    "aws_elasticsearch_domain": 25.0,
    "aws_redshift_cluster": 180.0,
}

# Limites par pipeline
MAX_EC2_INSTANCES = 1
MAX_SECURITY_GROUPS = 1


@dataclass
class GuardResult:
    approved: bool
    violations: list[str] = field(default_factory=list)
    estimated_monthly_cost: str = "FREE TIER"


def _parse_resources(terraform_code: str) -> list[dict]:
    """Extrait tous les blocs 'resource' du code Terraform."""
    resources = []
    # Match: resource "aws_type" "name" { ... }
    pattern = re.compile(
        r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
        re.DOTALL,
    )
    for match in pattern.finditer(terraform_code):
        resources.append({
            "type": match.group(1),
            "name": match.group(2),
            "body": match.group(3),
        })
    return resources


def _check_instance_type(body: str, resource_name: str, violations: list[str]) -> None:
    """Vérifie que le type d'instance EC2 est autorisé."""
    match = re.search(r'instance_type\s*=\s*"([^"]+)"', body)
    if match:
        itype = match.group(1)
        if itype not in ALLOWED_INSTANCE_TYPES:
            violations.append(
                f'aws_instance "{resource_name}": instance_type "{itype}" interdit '
                f'— seuls {sorted(ALLOWED_INSTANCE_TYPES)} sont autorisés (Free Tier)'
            )


def _check_s3_acl(body: str, resource_name: str, violations: list[str]) -> None:
    """Bloque les buckets S3 avec ACL public-read."""
    match = re.search(r'acl\s*=\s*"([^"]+)"', body)
    if match and match.group(1) == "public-read":
        violations.append(
            f'aws_s3_bucket "{resource_name}": acl="public-read" interdit '
            f'— exposition publique des données interdite'
        )


def _check_security_group_ports(body: str, resource_name: str, violations: list[str]) -> None:
    """Bloque les security groups avec port 0-65535 ouvert (all traffic)."""
    ingress_blocks = re.findall(r'ingress\s*\{([^}]+)\}', body, re.DOTALL)
    egress_blocks = re.findall(r'egress\s*\{([^}]+)\}', body, re.DOTALL)

    for direction, blocks in [("ingress", ingress_blocks), ("egress", egress_blocks)]:
        for block in blocks:
            from_port = re.search(r'from_port\s*=\s*(\d+)', block)
            to_port = re.search(r'to_port\s*=\s*(\d+)', block)
            if from_port and to_port:
                fp, tp = int(from_port.group(1)), int(to_port.group(1))
                if fp == 0 and tp == 65535:
                    violations.append(
                        f'aws_security_group "{resource_name}": règle {direction} '
                        f'0-65535 interdite — ouverture complète du trafic réseau'
                    )
                    break


def _estimate_cost(resources: list[dict]) -> float:
    """Calcule le coût mensuel estimé en USD."""
    total = 0.0
    for r in resources:
        total += RESOURCE_COSTS.get(r["type"], 5.0)  # 5$ par défaut pour ressource inconnue
    return total


def analyze_terraform(terraform_code: str) -> dict:
    """
    Analyse le code Terraform et retourne le résultat de la garde de sécurité.

    Args:
        terraform_code: Contenu du fichier .tf à analyser

    Returns:
        dict avec approved, violations, et estimated_monthly_cost
    """
    violations: list[str] = []
    resources = _parse_resources(terraform_code)

    # Compteurs par type
    ec2_count = 0
    sg_count = 0

    for resource in resources:
        rtype = resource["type"]
        rname = resource["name"]
        body = resource["body"]

        # 1. Ressources totalement interdites
        if rtype in FORBIDDEN_RESOURCES:
            violations.append(f'{rtype} "{rname}": {FORBIDDEN_RESOURCES[rtype]}')
            continue

        # 2. Vérifications spécifiques par type
        if rtype == "aws_instance":
            ec2_count += 1
            _check_instance_type(body, rname, violations)

        elif rtype == "aws_security_group":
            sg_count += 1
            _check_security_group_ports(body, rname, violations)

        elif rtype == "aws_s3_bucket":
            _check_s3_acl(body, rname, violations)

    # 3. Limites de ressources par pipeline
    if ec2_count > MAX_EC2_INSTANCES:
        violations.append(
            f"Limite dépassée: {ec2_count} instances EC2 détectées "
            f"— maximum autorisé: {MAX_EC2_INSTANCES} par pipeline"
        )

    if sg_count > MAX_SECURITY_GROUPS:
        violations.append(
            f"Limite dépassée: {sg_count} security groups détectés "
            f"— maximum autorisé: {MAX_SECURITY_GROUPS} par pipeline"
        )

    # 4. Estimation du coût
    monthly_cost = _estimate_cost(resources)
    if monthly_cost == 0.0:
        cost_label = "FREE TIER"
    else:
        cost_label = f"~${monthly_cost:.0f}/month"

    return GuardResult(
        approved=len(violations) == 0,
        violations=violations,
        estimated_monthly_cost=cost_label,
    ).__dict__


def guard_terraform(terraform_code: str) -> dict:
    """Point d'entrée principal — appelé par Jenkins avant terraform apply."""
    result = analyze_terraform(terraform_code)

    if not result["approved"]:
        result["violations"].insert(
            0,
            f"BLOCKED: {len(result['violations'])} violation(s) détectée(s) — terraform apply annulé"
        )

    return result
