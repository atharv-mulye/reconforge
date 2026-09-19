"""Basic, non-intrusive target reconnaissance helpers."""

import socket
from urllib.parse import urlparse


def resolve_hostname(hostname):
    """Return one IP address for a hostname, or None when it cannot be resolved."""
    try:
        address_info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None

    return address_info[0][4][0]


def collect_basic_reconnaissance(target_url):
    """Return basic target details for a URL that has already been validated."""
    parsed_url = urlparse(target_url)

    return {
        "original_target_url": target_url,
        "scheme": parsed_url.scheme,
        "hostname": parsed_url.hostname,
        "port": parsed_url.port,
        "resolved_ip": resolve_hostname(parsed_url.hostname),
    }
