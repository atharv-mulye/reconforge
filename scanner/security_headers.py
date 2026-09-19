"""Security-header checks that reuse the completed HTTP analysis result."""


SECURITY_HEADERS = [
    ("Content-Security-Policy", "High"),
    ("X-Content-Type-Options", "Medium"),
    ("X-Frame-Options", "Medium"),
    ("Strict-Transport-Security", "Medium"),
    ("Referrer-Policy", "Low"),
    ("Permissions-Policy", "Low"),
]


def analyze_security_headers(http_results):
    """Report whether important security headers were returned by HTTP analysis."""
    if http_results.get("status") != "completed":
        return {
            "status": "skipped",
            "message": "Security header analysis was skipped because HTTP analysis failed.",
            "findings": [],
        }

    response_headers = http_results.get("response_headers", {})
    normalized_headers = {
        header.lower(): value for header, value in response_headers.items()
    }
    findings = []

    for header_name, missing_severity in SECURITY_HEADERS:
        value = normalized_headers.get(header_name.lower())
        present = value is not None
        findings.append(
            {
                "header": header_name,
                "present": present,
                "value": value,
                "severity": "None" if present else missing_severity,
            }
        )

    return {
        "status": "completed",
        "message": "Security header analysis completed.",
        "findings": findings,
    }
