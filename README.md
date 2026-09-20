# ReconForge

### Web Application Security Assessment Platform

ReconForge is a Python-Flask based web application security assessment platform that automates initial reconnaissance, network/service scanning, HTTP security analysis, vulnerability assessment, risk classification, scan history, and VAPT report generation.

It is designed for **authorized security testing and local vulnerable web application labs**, such as OWASP Juice Shop and DVWA.

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
    │
    ▼
Target Validation
    │
    ▼
Reconnaissance
    │
    ▼
Nmap Service Scanning
    │
    ▼
HTTP Analysis
    │
    ▼
Security Header Analysis
    │
    ▼
Cookie Security Analysis
    │
    ▼
Controlled Vulnerability Assessment
    │
    ▼
Risk Classification
    │
    ▼
Results Dashboard
    │
    ├── Scan History
    │
    └── VAPT Report