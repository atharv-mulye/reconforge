import ipaddress
import re
import threading
import uuid

from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request, send_from_directory

from scanner.cookie_security import analyze_cookie_security
from scanner.database import (
    get_scan_history,
    init_database,
    save_scan_summary,
)
from scanner.http_scanner import analyze_http
from scanner.nmap_scanner import run_basic_nmap_scan
from scanner.reconnaissance import collect_basic_reconnaissance
from scanner.report_generator import (
    build_report_context,
    generate_html_report,
)
from scanner.risk_classifier import classify_risks
from scanner.security_headers import analyze_security_headers
from scanner.vulnerability_checks import analyze_vulnerabilities


app = Flask(__name__)
init_database()

HOSTNAME_PATTERN = re.compile(
    r"(?=.{1,253}$)(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)$"
)


# Temporary in-memory storage for active and completed scan jobs.
scan_jobs = {}
scan_jobs_lock = threading.Lock()


SCAN_STAGES = [
    "Target validation",
    "Reconnaissance",
    "Nmap service scan",
    "HTTP analysis",
    "Security headers",
    "Cookie security",
    "Vulnerability assessment",
    "Risk classification",
]


def create_scan_job(target_url):
    """Create a new background scan job."""
    job_id = str(uuid.uuid4())

    with scan_jobs_lock:
        scan_jobs[job_id] = {
            "status": "running",
            "target_url": target_url,
            "current_stage": "Target validation",
            "current_message": "Validating target URL...",
            "completed_stages": 0,
            "total_stages": len(SCAN_STAGES),
            "stage_status": {
                stage: "pending"
                for stage in SCAN_STAGES
            },
            "result": None,
            "error": None,
        }

    return job_id


def update_scan_progress(
    job_id,
    current_stage,
    current_message,
    completed_stages,
):
    """Update the visible progress of a background scan."""
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)

        if not job:
            return

        job["current_stage"] = current_stage
        job["current_message"] = current_message
        job["completed_stages"] = completed_stages

        for index, stage in enumerate(SCAN_STAGES):
            if index < completed_stages:
                job["stage_status"][stage] = "completed"
            elif stage == current_stage:
                job["stage_status"][stage] = "running"
            else:
                job["stage_status"][stage] = "pending"


def complete_scan_job(job_id, result):
    """Store completed scan results."""
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)

        if not job:
            return

        job["status"] = "completed"
        job["completed_stages"] = len(SCAN_STAGES)
        job["current_stage"] = "Complete"
        job["current_message"] = "Scan completed successfully."
        job["result"] = result

        for stage in SCAN_STAGES:
            job["stage_status"][stage] = "completed"


def fail_scan_job(job_id, error):
    """Store a background scan failure."""
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)

        if not job:
            return

        job["status"] = "error"
        job["current_stage"] = "Scan error"
        job["current_message"] = "The scan could not be completed."
        job["error"] = str(error)


def run_scan_job(job_id, target_url):
    """Run the complete scan in the background."""
    try:
        update_scan_progress(
            job_id,
            "Reconnaissance",
            "Collecting basic target information...",
            1,
        )

        reconnaissance = collect_basic_reconnaissance(target_url)

        update_scan_progress(
            job_id,
            "Nmap service scan",
            "Running Nmap port and service scan...",
            2,
        )

        nmap_results = run_basic_nmap_scan(
            reconnaissance["hostname"]
        )

        update_scan_progress(
            job_id,
            "HTTP analysis",
            "Analyzing the target HTTP response...",
            3,
        )

        http_results = analyze_http(target_url)

        update_scan_progress(
            job_id,
            "Security headers",
            "Checking HTTP security headers...",
            4,
        )

        security_headers_results = analyze_security_headers(
            http_results
        )

        update_scan_progress(
            job_id,
            "Cookie security",
            "Analyzing cookie security attributes...",
            5,
        )

        cookie_security_results = analyze_cookie_security(
            http_results
        )

        update_scan_progress(
            job_id,
            "Vulnerability assessment",
            "Performing controlled vulnerability assessment...",
            6,
        )

        vulnerability_results = analyze_vulnerabilities(
            http_results,
            security_headers_results,
            cookie_security_results,
        )

        update_scan_progress(
            job_id,
            "Risk classification",
            "Classifying observed findings by severity...",
            7,
        )

        risk_results = classify_risks(
            vulnerability_results
        )

        if (
            nmap_results["status"] == "completed"
            and http_results["status"] == "completed"
        ):
            success = (
                "Target accepted. Reconnaissance, Nmap service scanning, "
                "HTTP analysis, security header analysis, cookie analysis, "
                "and controlled vulnerability assessment are complete."
            )
        elif http_results["status"] == "completed":
            success = (
                "Target accepted. Reconnaissance, HTTP analysis, security "
                "header analysis, cookie analysis, and controlled "
                "vulnerability assessment are complete; the Nmap scan "
                "could not run."
            )
        elif nmap_results["status"] == "completed":
            success = (
                "Target accepted. Reconnaissance and Nmap service scanning "
                "are complete; HTTP analysis could not run."
            )
        else:
            success = (
                "Target accepted. Reconnaissance is complete; Nmap and "
                "HTTP analysis could not run."
            )

        try:
            save_scan_summary(
                target_url=target_url,
                final_url=http_results.get("final_url"),
                scanned_at=datetime.now(timezone.utc).isoformat(),
                http_status=http_results.get("status_code"),
                risk_results=risk_results,
            )
        except Exception as error:
            app.logger.warning(
                "Could not save scan history: %s",
                error,
            )

        report_context = build_report_context(
            target_url=target_url,
            reconnaissance=reconnaissance,
            nmap_results=nmap_results,
            http_results=http_results,
            security_headers_results=security_headers_results,
            cookie_security_results=cookie_security_results,
            vulnerability_results=vulnerability_results,
            risk_results=risk_results,
        )

        report_path = generate_html_report(report_context)
        report_filename = report_path.name

        result = {
            "success": success,
            "target_url": target_url,
            "reconnaissance": reconnaissance,
            "nmap_results": nmap_results,
            "http_results": http_results,
            "security_headers_results": security_headers_results,
            "cookie_security_results": cookie_security_results,
            "vulnerability_results": vulnerability_results,
            "risk_results": risk_results,
            "report_context": report_context,
            "report_filename": report_filename,
        }

        complete_scan_job(job_id, result)

    except Exception as error:
        app.logger.exception(
            "Background scan failed for job %s",
            job_id,
        )
        fail_scan_job(job_id, error)


@app.route("/")
def index():
    """Render the scanner landing page."""
    return render_template("index.html")


@app.route("/history")
def history():
    """Display previous scan summaries."""
    scans = get_scan_history()
    return render_template("history.html", scans=scans)


@app.route("/reports/<path:filename>")
def view_report(filename):
    """Serve a generated HTML VAPT report."""
    return send_from_directory(
        "reports",
        filename,
    )


def has_valid_hostname(hostname):
    """Accept localhost, IP addresses, and standard DNS hostnames."""
    if hostname == "localhost":
        return True

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return bool(HOSTNAME_PATTERN.fullmatch(hostname))


def validate_target_url(target_url):
    """Validate a target URL before starting a background scan."""
    if not target_url:
        raise ValueError("Please enter a target URL.")

    parsed_url = urlparse(target_url)

    if parsed_url.scheme not in {"http", "https"}:
        raise ValueError(
            "The URL must start with http:// or https://."
        )

    if not parsed_url.hostname:
        raise ValueError(
            "The URL must include a valid hostname."
        )

    parsed_url.port

    if not has_valid_hostname(parsed_url.hostname):
        raise ValueError(
            "The URL must include a valid hostname."
        )


@app.route("/scan", methods=["POST"])
def scan():
    """Validate the target URL and start a background scan."""
    target_url = request.form.get("target_url", "").strip()

    try:
        validate_target_url(target_url)
    except ValueError as error:
        return jsonify(
            {
                "status": "error",
                "message": str(error),
            }
        ), 400

    job_id = create_scan_job(target_url)

    worker = threading.Thread(
        target=run_scan_job,
        args=(job_id, target_url),
        daemon=True,
    )
    worker.start()

    return jsonify(
        {
            "status": "started",
            "job_id": job_id,
        }
    )


@app.route("/scan-status/<job_id>")
def scan_status(job_id):
    """Return the current progress of a background scan."""
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)

        if not job:
            return jsonify(
                {
                    "status": "error",
                    "message": "Scan job was not found.",
                }
            ), 404

        return jsonify(
            {
                "status": job["status"],
                "target_url": job["target_url"],
                "current_stage": job["current_stage"],
                "current_message": job["current_message"],
                "completed_stages": job["completed_stages"],
                "total_stages": job["total_stages"],
                "stage_status": job["stage_status"],
                "error": job["error"],
            }
        )


@app.route("/scan-results/<job_id>")
def scan_results(job_id):
    """Render the normal results page after a scan completes."""
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)

        if not job:
            return "Scan job was not found.", 404

        if job["status"] != "completed":
            return "Scan is not complete yet.", 409

        result = job["result"]

    return render_template(
        "index.html",
        success=result["success"],
        target_url=result["target_url"],
        reconnaissance=result["reconnaissance"],
        nmap_results=result["nmap_results"],
        http_results=result["http_results"],
        security_headers_results=result["security_headers_results"],
        cookie_security_results=result["cookie_security_results"],
        vulnerability_results=result["vulnerability_results"],
        risk_results=result["risk_results"],
        report_context=result["report_context"],
        report_filename=result["report_filename"],
    )


if __name__ == "__main__":
    app.run(debug=True)