"""Risk-summary classification for findings produced by vulnerability assessment."""


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
OVERALL_RISK_LEVELS = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Informational",
}


def empty_summary():
    """Return a zeroed severity summary with stable keys for reporting."""
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}


def normalize_severity(severity):
    """Convert known severity spelling variants to the project's canonical values."""
    normalized_value = str(severity or "Info").strip().lower()
    severity_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
    }
    return severity_map.get(normalized_value, "Info")


def classify_risks(vulnerability_results):
    """Summarize completed vulnerability findings without changing detection results."""
    if vulnerability_results.get("status") != "completed":
        return {
            "status": "skipped",
            "message": "Risk classification was skipped because vulnerability assessment did not complete.",
            "summary": empty_summary(),
            "overall_risk": "Not Available",
            "findings": [],
        }

    summary = empty_summary()
    classified_findings = []
    for finding in vulnerability_results.get("findings", []):
        classified_finding = dict(finding)
        severity = normalize_severity(finding.get("severity"))
        classified_finding["severity"] = severity
        classified_findings.append(classified_finding)
        summary[severity.lower()] += 1
        summary["total"] += 1

    overall_risk = "No Findings"
    for severity in SEVERITY_ORDER:
        if summary[severity.lower()]:
            overall_risk = OVERALL_RISK_LEVELS[severity]
            break

    return {
        "status": "completed",
        "message": (
            "Risk classification completed. Overall risk summarizes observed "
            "findings and is not a CVSS score or proof of exploitability."
        ),
        "summary": summary,
        "overall_risk": overall_risk,
        "findings": classified_findings,
    }
