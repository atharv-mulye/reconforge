"""HTML report generation for completed VAPT scan results."""

from datetime import datetime, timezone
from html import escape
from pathlib import Path


REPORT_DIRECTORY = Path("reports")


def safe_html(value):
    """Convert a value to safe HTML text."""
    if value is None:
        return "Not available"

    return escape(str(value))


def build_report_context(
    target_url,
    reconnaissance,
    nmap_results,
    http_results,
    security_headers_results,
    cookie_security_results,
    vulnerability_results,
    risk_results,
):
    """Build a single dictionary containing all data needed by the report."""
    return {
        "target_url": target_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "reconnaissance": reconnaissance,
        "nmap_results": nmap_results,
        "http_results": http_results,
        "security_headers_results": security_headers_results,
        "cookie_security_results": cookie_security_results,
        "vulnerability_results": vulnerability_results,
        "risk_results": risk_results,
    }


def generate_html_report(report_context):
    """Return an HTML report generated from completed scan results."""
    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = REPORT_DIRECTORY / f"vapt_report_{timestamp}.html"

    html = build_html_report(report_context)

    report_path.write_text(
        html,
        encoding="utf-8",
    )

    return report_path


def build_html_report(report_context):
    """Build the complete HTML document for a VAPT report."""
    risk_results = report_context["risk_results"]
    summary = risk_results.get("summary", {})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>VAPT Report - {safe_html(report_context["target_url"])}</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            color: #172033;
            line-height: 1.6;
        }}

        h1,
        h2,
        h3 {{
            color: #172033;
        }}

        h1 {{
            border-bottom: 2px solid #172033;
            padding-bottom: 10px;
        }}

        section {{
            margin-top: 30px;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-top: 20px;
        }}

        .summary-card {{
            padding: 15px;
            border: 1px solid #dbe3ee;
            border-radius: 8px;
            background: #f8fafc;
        }}

        .summary-label {{
            display: block;
            color: #526076;
            font-size: 0.85rem;
            font-weight: bold;
        }}

        .summary-value {{
            display: block;
            margin-top: 5px;
            font-size: 1.3rem;
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}

        th,
        td {{
            padding: 8px;
            border: 1px solid #dbe3ee;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #f3f6fa;
        }}

        .finding {{
            margin-top: 15px;
            padding: 15px;
            border: 1px solid #dbe3ee;
            border-radius: 8px;
        }}

        .finding h3 {{
            margin-top: 0;
        }}

        .footer {{
            margin-top: 40px;
            padding-top: 15px;
            border-top: 1px solid #dbe3ee;
            color: #526076;
            font-size: 0.9rem;
        }}

        @media print {{
            body {{
                margin: 20px;
            }}
        }}
    </style>
</head>

<body>

    <h1>Automated Web Application VAPT Report</h1>

    <p>
        This report contains observations produced by an authorized
        web application security assessment.
    </p>


    <section>
        <h2>Target Information</h2>

        <table>
            <tr>
                <th>Target URL</th>
                <td>{safe_html(report_context["target_url"])}</td>
            </tr>

            <tr>
                <th>Scan Date</th>
                <td>{safe_html(report_context["scanned_at"])}</td>
            </tr>

            <tr>
                <th>Hostname</th>
                <td>{safe_html(report_context["reconnaissance"].get("hostname"))}</td>
            </tr>

            <tr>
                <th>Resolved IP</th>
                <td>
                    {safe_html(
                        report_context["reconnaissance"].get("resolved_ip")
                        or "Not available"
                    )}
                </td>
            </tr>
        </table>
    </section>


    <section>
        <h2>Executive Summary</h2>

        <div class="summary">

            <div class="summary-card">
                <span class="summary-label">Overall Risk</span>
                <span class="summary-value">
                    {safe_html(risk_results.get("overall_risk", "Not Available"))}
                </span>
            </div>

            <div class="summary-card">
                <span class="summary-label">Total Findings</span>
                <span class="summary-value">
                    {safe_html(summary.get("total", 0))}
                </span>
            </div>

            <div class="summary-card">
                <span class="summary-label">Critical</span>
                <span class="summary-value">
                    {safe_html(summary.get("critical", 0))}
                </span>
            </div>

            <div class="summary-card">
                <span class="summary-label">High</span>
                <span class="summary-value">
                    {safe_html(summary.get("high", 0))}
                </span>
            </div>

            <div class="summary-card">
                <span class="summary-label">Medium</span>
                <span class="summary-value">
                    {safe_html(summary.get("medium", 0))}
                </span>
            </div>

            <div class="summary-card">
                <span class="summary-label">Low</span>
                <span class="summary-value">
                    {safe_html(summary.get("low", 0))}
                </span>
            </div>

            <div class="summary-card">
                <span class="summary-label">Informational</span>
                <span class="summary-value">
                    {safe_html(summary.get("info", 0))}
                </span>
            </div>

        </div>
    </section>


    <section>
        <h2>Reconnaissance</h2>

        <table>
            <tr>
                <th>Scheme</th>
                <td>
                    {safe_html(
                        report_context["reconnaissance"].get("scheme")
                    )}
                </td>
            </tr>

            <tr>
                <th>Hostname</th>
                <td>
                    {safe_html(
                        report_context["reconnaissance"].get("hostname")
                    )}
                </td>
            </tr>

            <tr>
                <th>Port</th>
                <td>
                    {safe_html(
                        report_context["reconnaissance"].get("port")
                        or "Not specified"
                    )}
                </td>
            </tr>

            <tr>
                <th>Resolved IP</th>
                <td>
                    {safe_html(
                        report_context["reconnaissance"].get("resolved_ip")
                        or "Could not resolve hostname"
                    )}
                </td>
            </tr>
        </table>
    </section>


    <section>
        <h2>Nmap Service Results</h2>

        <p>
            <strong>Status:</strong>
            {safe_html(
                report_context["nmap_results"].get(
                    "status",
                    "Not available"
                )
            )}
        </p>

        <p>
            {safe_html(
                report_context["nmap_results"].get(
                    "message",
                    ""
                )
            )}
        </p>

        <table>
            <tr>
                <th>Host</th>
                <th>IP Address</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Version</th>
            </tr>
"""

    # Read the structured Nmap host results.
    nmap_hosts = report_context["nmap_results"].get("results", [])

    # Track whether at least one open-port row was added.
    nmap_rows = 0

    for host in nmap_hosts:
        open_ports = host.get("open_ports", [])

        for port in open_ports:
            nmap_rows += 1

            html += f"""
            <tr>
                <td>
                    {safe_html(
                        host.get("hostname") or "Not reported"
                    )}
                </td>

                <td>
                    {safe_html(
                        host.get("ip_address") or "Not reported"
                    )}
                </td>

                <td>
                    {safe_html(
                        port.get("port") or "Not reported"
                    )}
                </td>

                <td>
                    {safe_html(
                        port.get("protocol") or "Not reported"
                    )}
                </td>

                <td>
                    {safe_html(
                        port.get("service") or "Unknown"
                    )}
                </td>

                <td>
                    {safe_html(
                        port.get("version") or "Not reported"
                    )}
                </td>
            </tr>
"""

    # Show an explicit message if Nmap completed but returned no open ports.
    if nmap_rows == 0:
        html += """
            <tr>
                <td colspan="6">
                    No open ports were reported by Nmap.
                </td>
            </tr>
"""

    html += """
        </table>
    </section>


    <section>
        <h2>HTTP Analysis</h2>

        <table>
"""

    http_results = report_context["http_results"]

    http_rows = [
        ("Requested URL", http_results.get("requested_url")),
        ("Final URL", http_results.get("final_url")),
        ("Status Code", http_results.get("status_code")),
        ("Response Time", http_results.get("response_time_ms")),
        ("Content-Type", http_results.get("content_type") or "Not provided"),
        ("Server", http_results.get("server") or "Not provided"),
        ("Redirects", http_results.get("redirect_count")),
    ]

    for label, value in http_rows:
        html += f"""
            <tr>
                <th>{safe_html(label)}</th>
                <td>{safe_html(value)}</td>
            </tr>
"""

    html += """
        </table>
    </section>


    <section>
        <h2>Security Headers</h2>

        <table>
            <tr>
                <th>Header</th>
                <th>Status</th>
                <th>Value</th>
                <th>Severity</th>
            </tr>
"""

    for finding in report_context["security_headers_results"].get(
        "findings",
        []
    ):
        html += f"""
            <tr>
                <td>
                    {safe_html(finding.get("header"))}
                </td>

                <td>
                    {"Present" if finding.get("present") else "Missing"}
                </td>

                <td>
                    {safe_html(
                        finding.get("value") or "Not provided"
                    )}
                </td>

                <td>
                    {safe_html(finding.get("severity"))}
                </td>
            </tr>
"""

    html += """
        </table>
    </section>


    <section>
        <h2>Cookie Security</h2>
"""

    cookies = report_context["cookie_security_results"].get(
        "cookies",
        []
    )

    if cookies:
        for cookie in cookies:
            html += f"""
        <div class="finding">
            <h3>{safe_html(cookie.get("name"))}</h3>

            <p>
                <strong>Secure:</strong>
                {"Yes" if cookie.get("secure") else "No"}
            </p>

            <p>
                <strong>HttpOnly:</strong>
                {"Yes" if cookie.get("httponly") else "No"}
            </p>

            <p>
                <strong>SameSite:</strong>
                {safe_html(
                    cookie.get("samesite") or "Not set"
                )}
            </p>
"""

            for finding in cookie.get("findings", []):
                html += f"""
            <p>
                <strong>
                    {safe_html(finding.get("severity"))}:
                </strong>

                {safe_html(finding.get("message"))}
            </p>
"""

            html += """
        </div>
"""
    else:
        html += """
        <p>No cookies were returned by the target.</p>
"""

    html += """
    </section>


    <section>
        <h2>Vulnerability Findings</h2>
"""

    findings = report_context["vulnerability_results"].get(
        "findings",
        []
    )

    if findings:
        for finding in findings:
            html += f"""
        <article class="finding">

            <h3>
                {safe_html(finding.get("title"))}
            </h3>

            <p>
                <strong>Severity:</strong>
                {safe_html(finding.get("severity"))}
            </p>

            <p>
                <strong>Description:</strong>
                {safe_html(finding.get("description"))}
            </p>

            <p>
                <strong>Evidence:</strong>
                {safe_html(finding.get("evidence"))}
            </p>

            <p>
                <strong>Recommendation:</strong>
                {safe_html(finding.get("recommendation"))}
            </p>

        </article>
"""
    else:
        html += """
        <p>
            No controlled vulnerability observations were identified
            from the collected data.
        </p>
"""

    html += """
    </section>


    <section>
        <h2>Risk Classification</h2>

        <table>
            <tr>
                <th>Overall Risk</th>
                <td>
"""

    html += safe_html(
        risk_results.get(
            "overall_risk",
            "Not Available"
        )
    )

    html += """
                </td>
            </tr>

            <tr>
                <th>Total Findings</th>
                <td>
"""

    html += safe_html(
        summary.get("total", 0)
    )

    html += """
                </td>
            </tr>

            <tr>
                <th>Critical</th>
                <td>
"""

    html += safe_html(
        summary.get("critical", 0)
    )

    html += """
                </td>
            </tr>

            <tr>
                <th>High</th>
                <td>
"""

    html += safe_html(
        summary.get("high", 0)
    )

    html += """
                </td>
            </tr>

            <tr>
                <th>Medium</th>
                <td>
"""

    html += safe_html(
        summary.get("medium", 0)
    )

    html += """
                </td>
            </tr>

            <tr>
                <th>Low</th>
                <td>
"""

    html += safe_html(
        summary.get("low", 0)
    )

    html += """
                </td>
            </tr>

            <tr>
                <th>Informational</th>
                <td>
"""

    html += safe_html(
        summary.get("info", 0)
    )

    html += """
                </td>
            </tr>
        </table>

        <p>
            Overall risk summarizes observed findings and is not a CVSS
            score or proof of exploitability.
        </p>
    </section>


    <div class="footer">
        Generated by Automated Web Application VAPT Scanner.
        This report is intended for authorized security assessment only.
    </div>

</body>
</html>
"""

    return html