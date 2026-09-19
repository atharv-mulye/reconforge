import ipaddress
import re
from urllib.parse import urlparse

from flask import Flask, render_template, request
from scanner.nmap_scanner import run_basic_nmap_scan
from scanner.reconnaissance import collect_basic_reconnaissance


app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)$"
)


@app.route("/")
def index():
    """Render the scanner landing page."""
    return render_template("index.html")


def has_valid_hostname(hostname):
    """Accept localhost, IP addresses, and standard DNS hostnames."""
    if hostname == "localhost":
        return True

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return bool(HOSTNAME_PATTERN.fullmatch(hostname))


@app.route("/scan", methods=["POST"])
def scan():
    """Accept and validate a target URL. Scanning is added in a later module."""
    target_url = request.form.get("target_url", "").strip()

    if not target_url:
        return render_template(
            "index.html", error="Please enter a target URL."
        ), 400

    try:
        parsed_url = urlparse(target_url)
        if parsed_url.scheme not in {"http", "https"}:
            raise ValueError("The URL must start with http:// or https://.")
        if not parsed_url.hostname:
            raise ValueError("The URL must include a valid hostname.")
        parsed_url.port  # Accessing the port catches invalid port values.
        if not has_valid_hostname(parsed_url.hostname):
            raise ValueError("The URL must include a valid hostname.")
    except ValueError as error:
        return render_template(
            "index.html", error=str(error), target_url=target_url
        ), 400

    reconnaissance = collect_basic_reconnaissance(target_url)
    nmap_results = run_basic_nmap_scan(reconnaissance["hostname"])

    if nmap_results["status"] == "completed":
        success = "Target accepted. Basic reconnaissance and Nmap service scanning are complete."
    else:
        success = "Target accepted. Basic reconnaissance is complete; the Nmap scan could not run."

    return render_template(
        "index.html",
        success=success,
        target_url=target_url,
        reconnaissance=reconnaissance,
        nmap_results=nmap_results,
    )


if __name__ == "__main__":
    app.run(debug=True)
