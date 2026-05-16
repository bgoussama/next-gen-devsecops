from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


# Stockage en memoire des rapports Jenkins.
# Les donnees sont perdues au redemarrage du backend.
_REPORTS: list[dict[str, Any]] = []


def _now_iso() -> str:
    """Retourne une date ISO UTC lisible par le frontend."""
    return datetime.now(timezone.utc).isoformat()


def save_report(report_data: dict) -> dict:
    """
    Sauvegarde un rapport Jenkins en memoire et retourne le rapport complet.

    github_branch_url et sonarqube_url restent optionnels: ils sont ajoutes
    uniquement si Jenkins les envoie dans le payload.
    """
    created_at = _now_iso()
    build_number = report_data.get("build_number", "")
    status = report_data.get("status", "")
    jenkins = report_data.get("jenkins") or {
        "job_name": "",
        "build_url": "",
        "pipeline_url": "",
        "executor": "Jenkins",
    }
    sast = report_data.get("sast") or {
        "tool": "SonarQube",
        "status": "EXECUTED",
        "project_key": "nextgen-devsecops",
        "dashboard_url": "http://localhost:9000/dashboard?id=nextgen-devsecops",
        "summary": "Analyse statique du code executee avec SonarQube pour detecter les bugs, vulnerabilites, code smells et hotspots de securite.",
    }
    cve_scan = report_data.get("cve_scan") or {
        "tool": "Trivy",
        "status": "EXECUTED",
        "target_image": f"nextgen-app:{build_number}",
        "severity_checked": ["HIGH", "CRITICAL"],
        "summary": "Scan de vulnerabilites realise sur l'image Docker generee par le pipeline.",
    }
    dast = report_data.get("dast") or {
        "tool": "OWASP ZAP",
        "status": "NOT_CONFIGURED",
        "summary": "Le test DAST n'est pas encore active dans cette version. Il peut etre ajoute apres le deploiement de l'application cible.",
    }
    security_summary = report_data.get("security_summary") or {
        "sast_executed": True,
        "cve_scan_executed": True,
        "dast_executed": False,
        "pipeline_result": status,
        "risk_level": "LOW" if status == "SUCCESS" else "UNKNOWN",
    }
    recommendations = report_data.get("recommendations") or [
        "Consulter le tableau de bord SonarQube pour analyser les bugs, vulnerabilites et hotspots.",
        "Verifier regulierement les vulnerabilites HIGH et CRITICAL detectees par Trivy.",
        "Ajouter OWASP ZAP pour completer l'analyse dynamique DAST.",
        "Conserver l'approche Shift-Left Security dans le pipeline CI/CD.",
    ]
    security_report = report_data.get("security_report") or (
        f"Le pipeline DevSecOps a ete execute avec le statut {status}. "
        "Jenkins a valide les artefacts, lance l'analyse SAST avec SonarQube, "
        "construit l'image Docker, puis execute un scan de vulnerabilites avec Trivy. "
        "Aucun test DAST n'est encore configure dans cette version."
    )

    report = {
        "id": str(uuid4()),
        "project": report_data.get("project", "Next-Gen DevSecOps"),
        "branch": report_data.get("branch", ""),
        "build_number": build_number,
        "status": status,
        "duration_ms": report_data.get("duration_ms", 0),
        "jenkins": jenkins,
        "sast": sast,
        "cve_scan": cve_scan,
        "dast": dast,
        "security_summary": security_summary,
        "recommendations": recommendations,
        "security_report": security_report,
        "timestamp": report_data.get("timestamp") or created_at,
        "created_at": created_at,
    }

    if report_data.get("sonarqube_url"):
        report["sonarqube_url"] = report_data["sonarqube_url"]

    if report_data.get("github_branch_url"):
        report["github_branch_url"] = report_data["github_branch_url"]

    # URL de l'app deployee sur EC2 — envoyee par Jenkins apres terraform output
    deployed_url = report_data.get("deployed_url")
    if deployed_url and deployed_url != "N/A":
        report["deployed_url"] = deployed_url

    _REPORTS.append(report)
    return report


def get_all_reports() -> list[dict]:
    """Retourne tous les rapports, du plus recent au plus ancien."""
    return list(reversed(_REPORTS))


def get_report_by_id(report_id: str) -> dict | None:
    """Retourne un rapport par son ID, ou None s'il n'existe pas."""
    return next((report for report in _REPORTS if report["id"] == report_id), None)
