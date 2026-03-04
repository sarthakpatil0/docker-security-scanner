"""
image_scanner.py
----------------
Scans a Docker image for known CVE vulnerabilities using Trivy.

Trivy is a free, open-source vulnerability scanner.
Install it with:  brew install trivy   OR   apt install trivy
Docs: https://github.com/aquasecurity/trivy
"""

import subprocess
import json
import shutil


def is_trivy_installed() -> bool:
    """Check if trivy is available on the system."""
    return shutil.which("trivy") is not None


def scan_image(image_name: str) -> dict:
    """
    Scan a Docker image using Trivy and return structured results.

    Args:
        image_name: Docker image name, e.g. "nginx:latest" or "myapp:v1"

    Returns:
        A dictionary with keys:
          - status:          "ok" | "error" | "trivy_not_found"
          - image:           the image name scanned
          - summary:         counts of vulns by severity
          - vulnerabilities: list of vulnerability dicts
          - raw:             full raw Trivy JSON output
    """

    # --- Guard: Trivy must be installed ---
    if not is_trivy_installed():
        return {
            "status": "trivy_not_found",
            "image": image_name,
            "message": (
                "Trivy is not installed. Install it first:\n"
                "  macOS:  brew install trivy\n"
                "  Ubuntu: sudo apt install trivy\n"
                "  Docs:   https://github.com/aquasecurity/trivy"
            ),
            "summary": {},
            "vulnerabilities": [],
        }

    # --- Run Trivy ---
    try:
        result = subprocess.run(
            [
                "trivy", "image",
                "--format", "json",   # machine-readable output
                "--quiet",            # suppress progress bar
                image_name
            ],
            capture_output=True,
            text=True,
            timeout=300             # 5 minute max
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "image": image_name,
            "message": "Scan timed out after 5 minutes.",
            "summary": {},
            "vulnerabilities": [],
        }
    except Exception as e:
        return {
            "status": "error",
            "image": image_name,
            "message": str(e),
            "summary": {},
            "vulnerabilities": [],
        }

    # --- Parse JSON output ---
    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "status": "error",
            "image": image_name,
            "message": f"Could not parse Trivy output:\n{result.stderr or result.stdout}",
            "summary": {},
            "vulnerabilities": [],
        }

    # --- Extract vulnerabilities ---
    all_vulns = []
    results_list = raw.get("Results", [])

    for target in results_list:
        target_name = target.get("Target", "unknown")
        for vuln in target.get("Vulnerabilities") or []:
            all_vulns.append({
                "id":           vuln.get("VulnerabilityID", "N/A"),
                "package":      vuln.get("PkgName", "N/A"),
                "installed":    vuln.get("InstalledVersion", "N/A"),
                "fixed_in":     vuln.get("FixedVersion", "Not fixed"),
                "severity":     vuln.get("Severity", "UNKNOWN"),
                "title":        vuln.get("Title", "No description"),
                "target":       target_name,
                "cvss_score":   _get_cvss_score(vuln),
                "references":   vuln.get("References", [])[:3],  # top 3 links
            })

    # --- Sort by severity ---
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_vulns.sort(key=lambda v: SEVERITY_ORDER.get(v["severity"], 99))

    # --- Summary counts ---
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in all_vulns:
        sev = v["severity"]
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "status":          "ok",
        "image":           image_name,
        "summary":         summary,
        "total":           len(all_vulns),
        "vulnerabilities": all_vulns,
        "raw":             raw,
    }


def _get_cvss_score(vuln: dict) -> str:
    """Extract the CVSS score from a vulnerability dict."""
    cvss = vuln.get("CVSS", {})
    for source in ("nvd", "redhat"):
        score = cvss.get(source, {}).get("V3Score")
        if score:
            return str(score)
    return "N/A"
