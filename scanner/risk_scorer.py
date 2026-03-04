"""
risk_scorer.py
--------------
Calculates a 0-100 security risk score for a Docker image + Dockerfile scan.

Scoring is based on 4 factors:
  1. Severity distribution (CRITICAL, HIGH, MEDIUM, LOW counts)
  2. Average CVSS score across all vulnerabilities
  3. Fixability (unfixable criticals are penalized less but still noted)
  4. Dockerfile risk multiplier (bad config makes CVEs more exploitable)
"""


# ─────────────────────────────────────────────
#  Score band definitions
# ─────────────────────────────────────────────

SCORE_BANDS = [
    (90, 100, "A", "SECURE",        "✅", "#3fb950", "Minimal risk. Safe to deploy."),
    (75,  89, "B", "LOW RISK",      "🟡", "#e3b341", "Minor issues. Fix in next sprint."),
    (50,  74, "C", "MODERATE RISK", "🟠", "#f0883e", "Real issues. Fix before next release."),
    (25,  49, "D", "HIGH RISK",     "🔴", "#f85149", "Serious issues. Do not ship."),
    (0,   24, "F", "CRITICAL RISK", "💀", "#ff0000", "Immediate action required."),
]


# ─────────────────────────────────────────────
#  Main scoring function
# ─────────────────────────────────────────────

def calculate_risk_score(image_scan: dict, lint_results: dict) -> dict:
    """
    Calculate a 0-100 risk score from scan results.

    Args:
        image_scan:   Output from image_scanner.scan_image()
        lint_results: Output from dockerfile_linter.lint_dockerfile()

    Returns:
        A dict with score, grade, label, breakdown, and recommendations.
    """

    breakdown = {}   # stores each penalty step for transparency

    # ── Step 1: Severity distribution penalty ─────────────────────────────
    summary = {}
    vulns   = []

    if image_scan and image_scan.get("status") == "ok":
        summary = image_scan.get("summary", {})
        vulns   = image_scan.get("vulnerabilities", [])

    critical_count = summary.get("CRITICAL", 0)
    high_count     = summary.get("HIGH",     0)
    medium_count   = summary.get("MEDIUM",   0)
    low_count      = summary.get("LOW",      0)

    # If no image scan, use lint findings for base severity counts
    if not vulns and lint_results and lint_results.get("status") == "ok":
        lint_sum    = lint_results.get("summary", {})
        critical_count = lint_sum.get("CRITICAL", 0)
        high_count     = lint_sum.get("HIGH",     0)
        medium_count   = lint_sum.get("MEDIUM",   0)
        low_count      = lint_sum.get("LOW",      0)

    severity_penalty = (
        critical_count * 15 +
        high_count     * 7  +
        medium_count   * 3  +
        low_count      * 1
    )
    severity_penalty = min(severity_penalty, 70)   # cap at 70
    breakdown["severity_penalty"] = {
        "value":   severity_penalty,
        "max":     70,
        "detail":  f"CRITICAL×{critical_count} + HIGH×{high_count} + MEDIUM×{medium_count} + LOW×{low_count}",
    }

    # ── Step 2: Average CVSS score penalty ────────────────────────────────
    cvss_scores = []
    for v in vulns:
        try:
            score = float(v.get("cvss_score", 0))
            if score > 0:
                cvss_scores.append(score)
        except (ValueError, TypeError):
            pass

    avg_cvss     = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0.0
    cvss_penalty = min(round(avg_cvss * 2), 20)   # max 20 points off
    breakdown["cvss_penalty"] = {
        "value":   cvss_penalty,
        "max":     20,
        "detail":  f"Average CVSS: {avg_cvss} × 2 = {cvss_penalty} points",
    }

    # ── Step 3: Fixability penalty ────────────────────────────────────────
    unfixable_criticals = sum(
        1 for v in vulns
        if v.get("severity") == "CRITICAL" and
        v.get("fixed_in", "").strip().lower() in ("", "not fixed", "n/a")
    )
    fixable_criticals   = critical_count - unfixable_criticals
    fixability_penalty  = min(fixable_criticals * 5 + unfixable_criticals * 2, 10)
    breakdown["fixability_penalty"] = {
        "value":              fixability_penalty,
        "max":                10,
        "fixable_criticals":  fixable_criticals,
        "unfixable_criticals": unfixable_criticals,
        "detail":             f"{fixable_criticals} fixable + {unfixable_criticals} unfixable CRITICALs",
    }

    # ── Step 4: Dockerfile risk multiplier ────────────────────────────────
    multiplier      = 1.0
    multiplier_note = "No Dockerfile issues"

    if lint_results and lint_results.get("status") == "ok":
        lint_summary      = lint_results.get("summary", {})
        lint_critical     = lint_summary.get("CRITICAL", 0)
        lint_high         = lint_summary.get("HIGH",     0)

        if lint_critical > 0:
            multiplier      = 1.3
            multiplier_note = f"Dockerfile has {lint_critical} CRITICAL issue(s) — CVEs are more exploitable"
        elif lint_high > 0:
            multiplier      = 1.15
            multiplier_note = f"Dockerfile has {lint_high} HIGH issue(s) — increases exploitability"

    breakdown["dockerfile_multiplier"] = {
        "value":  multiplier,
        "detail": multiplier_note,
    }

    # ── Step 5: Final score ───────────────────────────────────────────────
    raw_penalty   = severity_penalty + cvss_penalty + fixability_penalty
    total_penalty = round(raw_penalty * multiplier)
    final_score   = max(0, 100 - total_penalty)

    breakdown["raw_penalty"]   = raw_penalty
    breakdown["total_penalty"] = total_penalty
    breakdown["final_score"]   = final_score

    # ── Grade + band ──────────────────────────────────────────────────────
    grade, label, emoji, color, description = _get_band(final_score)

    # ── Recommendations ───────────────────────────────────────────────────
    recommendations = _build_recommendations(
        critical_count, high_count, fixable_criticals,
        unfixable_criticals, multiplier, lint_results
    )

    return {
        "score":           final_score,
        "grade":           grade,
        "label":           label,
        "emoji":           emoji,
        "color":           color,
        "description":     description,
        "avg_cvss":        avg_cvss,
        "total_vulns":     len(vulns),
        "breakdown":       breakdown,
        "recommendations": recommendations,
    }


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def _get_band(score: int):
    for low, high, grade, label, emoji, color, description in SCORE_BANDS:
        if low <= score <= high:
            return grade, label, emoji, color, description
    return "F", "CRITICAL RISK", "💀", "#ff0000", "Immediate action required."


def _build_recommendations(
    critical_count, high_count, fixable_criticals,
    unfixable_criticals, multiplier, lint_results
) -> list:
    """Build a prioritized list of recommendations based on findings."""
    recs = []

    if fixable_criticals > 0:
        recs.append({
            "priority": 1,
            "action":   f"Patch {fixable_criticals} fixable CRITICAL vulnerability/vulnerabilities immediately.",
            "why":      "Fixable CRITICALs are the highest-priority — a patch exists and you should apply it.",
        })

    if unfixable_criticals > 0:
        recs.append({
            "priority": 2,
            "action":   f"Evaluate {unfixable_criticals} unfixable CRITICAL vulnerability/vulnerabilities.",
            "why":      "No patch exists yet. Consider switching to a different base image or adding compensating controls.",
        })

    if multiplier >= 1.3:
        recs.append({
            "priority": 3,
            "action":   "Fix CRITICAL Dockerfile issues (e.g. running as root, hardcoded secrets).",
            "why":      "Bad Dockerfile config makes existing CVEs far easier to exploit.",
        })
    elif multiplier >= 1.15:
        recs.append({
            "priority": 3,
            "action":   "Fix HIGH Dockerfile issues to reduce exploitability.",
            "why":      "Dockerfile misconfigurations increase the blast radius of any CVE.",
        })

    if high_count > 10:
        recs.append({
            "priority": 4,
            "action":   f"Reduce HIGH vulnerabilities (currently {high_count}) by updating base image.",
            "why":      "Switching to a minimal base like alpine or distroless eliminates most package-level CVEs.",
        })

    if not recs:
        recs.append({
            "priority": 1,
            "action":   "Maintain current security posture.",
            "why":      "No critical actions required. Continue scanning regularly.",
        })

    return recs


# ─────────────────────────────────────────────
#  Console printer (for CLI output)
# ─────────────────────────────────────────────

def print_risk_score(risk: dict):
    """Print a formatted risk score block to the terminal."""

    score = risk["score"]
    grade = risk["grade"]
    label = risk["label"]

    # Build visual progress bar
    filled = int(score / 5)
    empty  = 20 - filled
    bar    = "█" * filled + "░" * empty

    b = risk["breakdown"]
    sev_val  = b["severity_penalty"]["value"] if isinstance(b["severity_penalty"], dict) else b["severity_penalty"]
    cvss_val = b["cvss_penalty"]["value"]     if isinstance(b["cvss_penalty"],     dict) else b["cvss_penalty"]
    fix_val  = b["fixability_penalty"]["value"] if isinstance(b["fixability_penalty"], dict) else b["fixability_penalty"]
    mult     = b["dockerfile_multiplier"]["value"]
    mult_note= b["dockerfile_multiplier"]["detail"]

    print(f"\n{'─'*60}")
    print(f"  SECURITY RISK SCORE")
    print(f"{'─'*60}")
    print(f"  {bar}  {score}/100")
    print(f"  Grade: {grade}  |  {risk['emoji']} {label}")
    print(f"  {risk['description']}")
    print(f"\n  Average CVSS: {risk['avg_cvss']}  |  Total Vulns: {risk['total_vulns']}")
    print(f"\n  Penalty Breakdown:")
    print(f"    Severity counts    : -{sev_val} pts")
    print(f"    CVSS average       : -{cvss_val} pts")
    print(f"    Fixability         : -{fix_val} pts")
    print(f"    Dockerfile risk    :  x{mult}  ({mult_note})")
    print(f"    Total penalty      :  {b['total_penalty']} pts")

    print(f"\n  Recommendations:")
    for r in risk["recommendations"]:
        print(f"    [{r['priority']}] {r['action']}")
        print(f"        Why: {r['why']}")

    print(f"{'─'*60}\n")