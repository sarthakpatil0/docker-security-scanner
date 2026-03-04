"""
dockerfile_linter.py
--------------------
Lints a Dockerfile for security best practices and misconfigurations.

No external dependencies needed — uses pure Python regex.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


# ─────────────────────────────────────────────
#  Data model for a single finding
# ─────────────────────────────────────────────

@dataclass
class Finding:
    rule_id:   str
    severity:  str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title:     str
    message:   str
    line_num:  Optional[int] = None
    line_text: Optional[str] = None
    fix:       Optional[str] = None


# ─────────────────────────────────────────────
#  All lint rules
# ─────────────────────────────────────────────

RULES = [
    # --- Image tag rules ---
    {
        "id":       "DF001",
        "severity": "HIGH",
        "title":    "Avoid :latest tag",
        "pattern":  r"^FROM\s+\S+:latest",
        "message":  "Using ':latest' is unpredictable — the image changes silently over time.",
        "fix":      "Pin to a specific version, e.g.  FROM nginx:1.25.3",
        "scope":    "line",
    },
    {
        "id":       "DF002",
        "severity": "MEDIUM",
        "title":    "Untagged FROM instruction",
        "pattern":  r"^FROM\s+[a-zA-Z0-9_/.-]+\s*$",
        "message":  "No tag specified — Docker will use ':latest' implicitly.",
        "fix":      "Always specify a version tag, e.g.  FROM ubuntu:22.04",
        "scope":    "line",
    },

    # --- User / privilege rules ---
    {
        "id":       "DF003",
        "severity": "CRITICAL",
        "title":    "Container runs as root",
        "pattern":  r"^USER\s+(root|0)\s*$",
        "message":  "Running as root gives an attacker full control if the container is compromised.",
        "fix":      "Create a non-root user:  RUN useradd -r appuser && USER appuser",
        "scope":    "line",
    },
    {
        "id":       "DF004",
        "severity": "HIGH",
        "title":    "No USER instruction found",
        "pattern":  None,
        "message":  "No USER instruction detected — container will run as root by default.",
        "fix":      "Add  USER <non-root-user>  before the CMD/ENTRYPOINT instruction.",
        "scope":    "global_missing",
        "check_missing": "USER",
    },

    # --- Secrets / sensitive data ---
    {
        "id":       "DF005",
        "severity": "CRITICAL",
        "title":    "Hardcoded secret in ENV",
        "pattern":  r"^ENV\s+.*(password|passwd|secret|api_key|token|private_key)\s*[=\s]\s*\S+",
        "message":  "Secrets baked into ENV instructions are visible in the image layers forever.",
        "fix":      "Use Docker secrets or pass secrets at runtime:  docker run -e SECRET=$SECRET",
        "scope":    "line",
        "flags":    re.IGNORECASE,
    },
    {
        "id":       "DF006",
        "severity": "CRITICAL",
        "title":    "Hardcoded secret in ARG",
        "pattern":  r"^ARG\s+.*(password|passwd|secret|api_key|token)\s*=\s*\S+",
        "message":  "Build ARG values with secrets are stored in image history (docker history).",
        "fix":      "Pass secrets via  --secret  flag in BuildKit instead.",
        "scope":    "line",
        "flags":    re.IGNORECASE,
    },

    # --- Dangerous RUN patterns ---
    {
        "id":       "DF007",
        "severity": "CRITICAL",
        "title":    "curl | bash anti-pattern",
        "pattern":  r"(curl|wget)\s+.*\|\s*(bash|sh)",
        "message":  "Piping a remote script directly to a shell is a major supply-chain risk.",
        "fix":      "Download the script first, verify its checksum, then execute it.",
        "scope":    "line",
    },
    {
        "id":       "DF008",
        "severity": "HIGH",
        "title":    "sudo used in RUN",
        "pattern":  r"^RUN\s+.*\bsudo\b",
        "message":  "Using sudo inside a container is unnecessary and increases attack surface.",
        "fix":      "Use USER root sparingly or switch users properly.",
        "scope":    "line",
    },
    {
        "id":       "DF009",
        "severity": "MEDIUM",
        "title":    "chmod 777 detected",
        "pattern":  r"chmod\s+(777|a\+rwx|o\+rwx)",
        "message":  "World-writable permissions allow any process to modify critical files.",
        "fix":      "Use the minimum permissions needed, e.g.  chmod 755",
        "scope":    "line",
    },
    {
        "id":       "DF010",
        "severity": "MEDIUM",
        "title":    "Package cache not cleaned",
        "pattern":  r"apt-get install(?!.*rm -rf /var/lib/apt)",
        "message":  "Leaving apt cache bloats the image and increases the attack surface.",
        "fix":      "Add  && rm -rf /var/lib/apt/lists/*  at the end of your apt-get install line.",
        "scope":    "line",
    },

    # --- ADD vs COPY ---
    {
        "id":       "DF011",
        "severity": "LOW",
        "title":    "ADD used instead of COPY",
        "pattern":  r"^ADD\s+(?!https?://)\S+\s+\S+",
        "message":  "ADD has implicit behaviors (auto-extraction). COPY is safer and more explicit.",
        "fix":      "Replace  ADD  with  COPY  unless you specifically need URL fetching or auto-extraction.",
        "scope":    "line",
    },

    # --- HEALTHCHECK ---
    {
        "id":       "DF012",
        "severity": "INFO",
        "title":    "No HEALTHCHECK instruction",
        "pattern":  None,
        "message":  "Without a HEALTHCHECK, Docker cannot automatically detect if your app is broken.",
        "fix":      "Add:  HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
        "scope":    "global_missing",
        "check_missing": "HEALTHCHECK",
    },
    {
        "id":       "DF013",
        "severity": "HIGH",
        "title":    "Insecure tool installed",
        "pattern":  r"apt-get install.*\btelnet\b",
        "message":  "Telnet sends data in plain text — never install it in a container.",
        "fix":      "Use SSH or encrypted alternatives instead.",
        "scope":    "line",
    },
    # ----- FTP connection ------
    {
        "id":       "DF014",
        "severity": "HIGH",
        "title":    "Insecure tool installed",
        "pattern": r"apt-get install.*\bftp\b",
        "message":  "FTP sends data in plain text — never install it in a container.",
        "fix":      "Use SFTP or encrypted alternatives instead.",
        "scope":    "line",
    },
    # ----- Skipping SSL verification ------
    {
        "id":       "DF015",
        "severity": "MEDIUM",
        "title":    "SSL verification skipped in package installation",
        "pattern": r"wget.*--no-check-certificate",
        "message":  "Skipping SSL verification allows MITM attacks when downloading packages.",
        "fix":      "Remove  --no-check-certificate  and ensure proper CA certificates are installed.",
        "scope":    "line",
    },
    {
        "id":       "DF014",
        "severity": "CRITICAL",
        "title":    "AWS Access Key detected",
        "pattern":  r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIPA)[A-Z0-9]{16}(?![A-Z0-9])",
        "message":  "AWS key hardcoded in Dockerfile — rotate it immediately.",
        "fix":      "Use IAM roles or pass via environment variables at runtime.",
        "scope":    "line",
    },

]


# ─────────────────────────────────────────────
#  Main linting function
# ─────────────────────────────────────────────

def lint_dockerfile(filepath: str) -> dict:
    """
    Lint a Dockerfile and return structured findings.

    Args:
        filepath: Path to the Dockerfile.

    Returns:
        A dict with:
          - status:   "ok" | "error"
          - filepath: the path linted
          - summary:  counts by severity
          - findings: list of Finding dicts
    """

    # --- Read file ---
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        return {"status": "error", "message": f"File not found: {filepath}", "findings": [], "summary": {}}
    except Exception as e:
        return {"status": "error", "message": str(e), "findings": [], "summary": {}}

    full_text = "".join(raw_lines)
    findings: List[Finding] = []

    # --- Per-line rules ---
    for rule in RULES:
        if rule["scope"] == "line" and rule["pattern"]:
            regex_flags = rule.get("flags", 0)
            pattern = re.compile(rule["pattern"], regex_flags)
            for i, line in enumerate(raw_lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#"):   # skip comments
                    continue
                if pattern.search(stripped):
                    findings.append(Finding(
                        rule_id=rule["id"],
                        severity=rule["severity"],
                        title=rule["title"],
                        message=rule["message"],
                        line_num=i,
                        line_text=stripped[:120],
                        fix=rule.get("fix"),
                    ))

    # --- Global "missing instruction" rules ---
    for rule in RULES:
        if rule["scope"] == "global_missing":
            keyword = rule["check_missing"]
            # Check if the keyword exists as an instruction anywhere
            found = any(
                line.strip().startswith(keyword)
                for line in raw_lines
                if not line.strip().startswith("#")
            )
            if not found:
                findings.append(Finding(
                    rule_id=rule["id"],
                    severity=rule["severity"],
                    title=rule["title"],
                    message=rule["message"],
                    fix=rule.get("fix"),
                ))

    # --- Summary ---
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    # --- Sort by severity ---
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    return {
        "status":   "ok",
        "filepath": filepath,
        "total":    len(findings),
        "summary":  summary,
        "findings": [_finding_to_dict(f) for f in findings],
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "rule_id":   f.rule_id,
        "severity":  f.severity,
        "title":     f.title,
        "message":   f.message,
        "line_num":  f.line_num,
        "line_text": f.line_text,
        "fix":       f.fix,
    }