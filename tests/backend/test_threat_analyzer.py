import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")))

from backend.services.threat_analyzer import analyze_threats


SECURE_JENKINSFILE = """
pipeline {
  agent any
  stages {
    stage('Security Scan') {
      steps {
        sh 'trivy image nextgen-app:${BUILD_NUMBER}'
      }
    }
  }
}
"""

SECURE_TERRAFORM = """
resource "aws_security_group" "app" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
"""

SECURE_DOCKERFILE = """
FROM nginx:1.25-alpine
RUN adduser -D -H appuser
USER appuser
"""

SECURE_K8S = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: nextgen-app:1.2.3
          env:
            - name: API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: app-secret
                  key: token
"""


def technique(result, technique_id):
    return next(item for item in result.techniques if item["id"] == technique_id)


def test_secure_artifacts_return_low_risk():
    """Les artefacts avec secrets externes, scan et non-root doivent etre proteges."""
    result = analyze_threats(
        jenkinsfile=SECURE_JENKINSFILE,
        terraform=SECURE_TERRAFORM,
        dockerfile=SECURE_DOCKERFILE,
        k8s_manifest=SECURE_K8S,
    )

    assert result.score == 100
    assert result.risk_level == "LOW"
    assert len(result.techniques) == 5
    assert all(item["status"] == "PROTECTED" for item in result.techniques)


def test_risky_artifacts_reduce_score_and_mark_expected_techniques():
    """Les patterns dangereux doivent baisser le score de 20 points chacun."""
    result = analyze_threats(
        jenkinsfile="pipeline { stages { stage('Build') { steps { sh 'npm install' } } } }",
        terraform="""
resource "aws_security_group" "open" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_user" "admin" { name = "admin" }
""",
        dockerfile="""
FROM node:latest
ENV PASSWORD="supersecret123"
""",
        k8s_manifest="image: api:latest",
    )

    assert result.score == 0
    assert result.risk_level == "CRITICAL"
    assert technique(result, "T1552")["status"] == "AT_RISK"
    assert technique(result, "T1190")["status"] == "AT_RISK"
    assert technique(result, "T1525")["status"] == "AT_RISK"
    assert technique(result, "T1195")["status"] == "AT_RISK"
    assert technique(result, "T1078")["status"] == "AT_RISK"
    assert result.recommendations


def test_unknown_status_does_not_reduce_score():
    """UNKNOWN signale une preuve insuffisante sans penalite de score."""
    result = analyze_threats(
        jenkinsfile=SECURE_JENKINSFILE,
        terraform="",
        dockerfile="",
        k8s_manifest="",
    )

    assert result.score == 100
    assert technique(result, "T1190")["status"] == "UNKNOWN"
    assert technique(result, "T1525")["status"] == "UNKNOWN"
