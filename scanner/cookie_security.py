"""Passive cookie-attribute checks using data from HTTP analysis."""

from http.cookies import CookieError, SimpleCookie


def build_findings(secure, httponly, samesite):
    """Return observations for cookie attributes that are not present."""
    findings = []

    if not secure:
        findings.append(
            {
                "attribute": "Secure",
                "present": False,
                "severity": "Medium",
                "message": "Cookie does not have the Secure attribute.",
            }
        )
    if not httponly:
        findings.append(
            {
                "attribute": "HttpOnly",
                "present": False,
                "severity": "Medium",
                "message": "Cookie does not have the HttpOnly attribute.",
            }
        )
    if not samesite:
        findings.append(
            {
                "attribute": "SameSite",
                "present": False,
                "severity": "Low",
                "message": "Cookie does not have a SameSite attribute.",
            }
        )

    return findings


def analyze_cookie_security(http_results):
    """Analyze Set-Cookie values stored during completed HTTP analysis."""
    if http_results.get("status") != "completed":
        return {
            "status": "skipped",
            "message": "Cookie security analysis was skipped because HTTP analysis failed.",
            "cookies": [],
        }

    cookies = []
    for set_cookie_header in http_results.get("set_cookie_headers", []):
        parsed_cookies = SimpleCookie()
        try:
            parsed_cookies.load(set_cookie_header)
        except CookieError:
            continue

        for name, morsel in parsed_cookies.items():
            secure = bool(morsel["secure"])
            httponly = bool(morsel["httponly"])
            samesite = morsel["samesite"] or None
            cookies.append(
                {
                    "name": name,
                    "secure": secure,
                    "httponly": httponly,
                    "samesite": samesite,
                    "findings": build_findings(secure, httponly, samesite),
                }
            )

    return {
        "status": "completed",
        "message": "Cookie security analysis completed.",
        "cookies": cookies,
    }
