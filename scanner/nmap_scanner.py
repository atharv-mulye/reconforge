"""Small wrapper around the system Nmap executable for authorized lab scans."""

import shutil
import subprocess
import xml.etree.ElementTree as element_tree


def build_service_version(service):
    """Combine optional Nmap service details into one readable value."""
    if service is None:
        return None

    details = [
        service.get("product"),
        service.get("version"),
        service.get("extrainfo"),
    ]
    return " ".join(detail for detail in details if detail) or None


def parse_nmap_xml(xml_output):
    """Convert Nmap XML output into simple Python dictionaries."""
    root = element_tree.fromstring(xml_output)
    hosts = []

    for host in root.findall("host"):
        addresses = {
            address.get("addrtype"): address.get("addr")
            for address in host.findall("address")
        }
        hostname = host.find("hostnames/hostname")
        open_ports = []

        for port in host.findall("ports/port"):
            if port.find("state").get("state") != "open":
                continue

            service = port.find("service")
            open_ports.append(
                {
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if service is not None else None,
                    "version": build_service_version(service),
                }
            )

        hosts.append(
            {
                "hostname": hostname.get("name") if hostname is not None else None,
                "ip_address": addresses.get("ipv4") or addresses.get("ipv6"),
                "open_ports": open_ports,
            }
        )

    return hosts


def run_basic_nmap_scan(target_host):
    """Run a basic TCP service scan and return structured results.

    This function expects a hostname or IP address already validated by Flask.
    It runs only after an explicit form submission; it does not run automatically.
    """
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return {
            "target": target_host,
            "available": False,
            "status": "unavailable",
            "message": "Nmap is not installed or could not be found on this system.",
            "results": [],
        }

    command = [
        nmap_path,
        "-sT",
        "-sV",
        "--version-light",
        "-oX",
        "-",
        target_host,
    ]

    try:
        completed_process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError:
        return {
            "target": target_host,
            "available": False,
            "status": "unavailable",
            "message": "Nmap is not installed or could not be found on this system.",
            "results": [],
        }
    except subprocess.TimeoutExpired:
        return {
            "target": target_host,
            "available": True,
            "status": "error",
            "message": "Nmap did not finish within 120 seconds.",
            "results": [],
        }

    if completed_process.returncode != 0:
        error_message = completed_process.stderr.strip() or "Nmap returned an error."
        return {
            "target": target_host,
            "available": True,
            "status": "error",
            "message": error_message,
            "results": [],
        }

    try:
        hosts = parse_nmap_xml(completed_process.stdout)
    except element_tree.ParseError:
        return {
            "target": target_host,
            "available": True,
            "status": "error",
            "message": "Nmap returned output that could not be read.",
            "results": [],
        }

    return {
        "target": target_host,
        "available": True,
        "status": "completed",
        "message": "Basic Nmap scan completed.",
        "results": hosts,
    }
