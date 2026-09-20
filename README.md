````md
# ReconForge

### Web Application Security Assessment Platform

ReconForge is a Python-Flask based web application security assessment platform that automates initial reconnaissance, network/service scanning, HTTP security analysis, vulnerability assessment, risk classification, scan history, and VAPT report generation.

It is designed for **authorized security testing and local vulnerable web application labs**, such as OWASP Juice Shop and DVWA.

> **For authorized security testing and local vulnerable web application labs only.**

---

## Features

- Target URL validation
- Basic hostname and IP reconnaissance
- DNS/hostname resolution
- Nmap-based service and version scanning
- HTTP response analysis
- Security header analysis
- Cookie security analysis
- Controlled vulnerability assessment
- Severity-based risk classification
- Live scan progress tracking
- Scan results dashboard
- SQLite-based scan history
- Clear scan history
- VAPT report generation
- Local lab testing with OWASP Juice Shop

---

## Scan Workflow

ReconForge follows a structured security assessment workflow:

```text
Target URL
    |
    v
Target Validation
    |
    v
Reconnaissance
    |
    v
Nmap Service Scanning
    |
    v
HTTP Analysis
    |
    v
Security Header Analysis
    |
    v
Cookie Security Analysis
    |
    v
Controlled Vulnerability Assessment
    |
    v
Risk Classification
    |
    v
Results Dashboard
    |
    +----> Scan History
    |
    +----> VAPT Report
````

---

## Technology Stack

| Component           | Technology            |
| ------------------- | --------------------- |
| Backend             | Python                |
| Web Framework       | Flask                 |
| Frontend            | HTML, CSS, JavaScript |
| Database            | SQLite                |
| Network Scanner     | Nmap                  |
| HTTP Analysis       | Python Requests       |
| Reporting           | HTML                  |
| Testing Environment | Kali Linux            |
| Vulnerable Target   | OWASP Juice Shop      |
| Version Control     | Git / GitHub          |

---

## Security Assessment

### Target Validation

Validates the target URL before starting the assessment.

* Supports HTTP and HTTPS
* Validates the hostname
* Validates the supplied URL
* Rejects invalid target URLs before scanning

### Reconnaissance

Collects basic target information:

* Target URL
* Scheme
* Hostname
* Port
* Resolved IP address

### Nmap Service Scanning

Performs controlled TCP service and lightweight version detection.

The project avoids aggressive scanning, NSE exploitation scripts, and destructive techniques.

### HTTP Analysis

Collects:

* HTTP status code
* Final URL
* Redirect count
* Response time
* Content type
* Server information
* HTTP headers
* `Set-Cookie` headers

### Security Header Analysis

Checks commonly recommended security headers:

* `Content-Security-Policy`
* `X-Content-Type-Options`
* `X-Frame-Options`
* `Strict-Transport-Security`
* `Referrer-Policy`
* `Permissions-Policy`

### Cookie Security Analysis

Checks cookie security attributes:

* `Secure`
* `HttpOnly`
* `SameSite`

### Vulnerability Assessment

Identifies potential security weaknesses using information already collected during the scan.

No destructive exploitation or attack payloads are used.

The assessment is intended to identify potential issues for further manual verification rather than demonstrate successful exploitation.

### Risk Classification

Findings are classified using the following severity levels:

| Severity | Description                   |
| -------- | ----------------------------- |
| Critical | Highest observed risk level   |
| High     | Significant security concern  |
| Medium   | Moderate security concern     |
| Low      | Lower-impact security concern |
| Info     | Informational observation     |

The classification is an assessment aid and is **not a formal CVSS score or proof of exploitability**.

---

## Live Scan Progress

ReconForge provides live progress tracking for the scan workflow:

| Stage | Description                    |
| ----- | ------------------------------ |
| 1     | Target validation              |
| 2     | Reconnaissance                 |
| 3     | Nmap service scanning          |
| 4     | HTTP analysis                  |
| 5     | Security headers               |
| 6     | Cookie security                |
| 7     | Vulnerability assessment       |
| 8     | Risk classification and report |

The scan runs in the background while the frontend periodically checks the scan status.

---

## Results Dashboard

After a scan completes, ReconForge displays:

* Target information
* Reconnaissance results
* Nmap results
* HTTP analysis
* Security header results
* Cookie security results
* Vulnerability findings
* Risk classification
* Finding severity summary

---

## Scan History

ReconForge stores completed scan summaries using SQLite.

The history includes:

| Information         | Stored |
| ------------------- | ------ |
| Scan ID             | Yes    |
| Target URL          | Yes    |
| Final URL           | Yes    |
| Scan timestamp      | Yes    |
| HTTP status         | Yes    |
| Overall risk        | Yes    |
| Total findings      | Yes    |
| Critical count      | Yes    |
| High count          | Yes    |
| Medium count        | Yes    |
| Low count           | Yes    |
| Informational count | Yes    |

The history page also provides an option to clear stored scan-history records.

---

## VAPT Report

ReconForge generates an HTML-based VAPT report after a scan.

The report can contain:

* Target information
* Reconnaissance results
* Nmap results
* HTTP analysis
* Security header analysis
* Cookie analysis
* Vulnerability findings
* Risk classification
* Recommendations

---

## Testing Environment

ReconForge is designed to be tested in a controlled cybersecurity lab.

```text
Kali Linux
|
+-- ReconForge
|
+-- Nmap
|
+-- OWASP Juice Shop
        |
        +-- localhost:3000
```

OWASP Juice Shop is used as the primary vulnerable web application for testing.

---

## Installation

### Requirements

* Python 3.x
* Git
* Nmap
* Web browser
* OWASP Juice Shop for local testing

### Clone Repository

```bash
git clone https://github.com/atharv-mulye/reconforge.git
cd reconforge
```

### Create Virtual Environment

#### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

#### Linux / Kali Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Verify Nmap

```bash
nmap --version
```

### Start ReconForge

```bash
python app.py
```

Open the application at:

```text
http://127.0.0.1:5000
```

---

## Project Structure

```text
reconforge/
|
+-- app.py
|
+-- scanner/
|   +-- __init__.py
|   +-- reconnaissance.py
|   +-- nmap_scanner.py
|   +-- http_scanner.py
|   +-- security_headers.py
|   +-- cookie_security.py
|   +-- vulnerability_checks.py
|   +-- risk_classifier.py
|   +-- database.py
|   +-- report_generator.py
|
+-- templates/
|   +-- index.html
|   +-- history.html
|
+-- static/
|   +-- css/
|   |   +-- style.css
|   |
|   +-- js/
|       +-- script.js
|
+-- .gitignore
+-- README.md
+-- requirements.txt
```

---

## Security and Authorized Use

ReconForge is intended for:

* Cybersecurity education
* Security learning
* Authorized penetration testing
* Local vulnerable application labs
* Academic cybersecurity projects

> **Only scan systems that you own or have explicit permission to test.**

Do not use ReconForge to scan, assess, or test systems without authorization.

---

## Scope Limitations

ReconForge intentionally does not provide:

* Destructive exploitation
* Credential attacks
* Brute-force attacks
* Denial-of-service testing
* Malware functionality
* Persistence mechanisms
* Stealth or evasion functionality
* Unauthorized scanning

The goal is to provide an automated security assessment workflow rather than a full exploitation framework.

---

## Limitations

ReconForge is an assessment and learning tool, not a replacement for a professional manual penetration test.

Some findings are based on configuration and response analysis and may require manual verification.

> **Finding detected != Confirmed successful exploitation**

Manual security testing and validation may still be required.

---

## Project Status

ReconForge currently provides an end-to-end automated web application security assessment workflow covering:

* Reconnaissance
* Nmap scanning
* HTTP analysis
* Security headers
* Cookie security
* Vulnerability assessment
* Risk classification
* Live scan progress
* Scan history
* VAPT report generation

---

## Disclaimer

ReconForge is developed for **educational, research, and authorized security testing purposes**.

The developer is not responsible for unauthorized or unlawful use of this project.

```

Available next action: :contentReference[oaicite:0]{index=0}
```
