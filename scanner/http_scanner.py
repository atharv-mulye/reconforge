"""Basic, non-intrusive HTTP analysis for authorized targets."""

import requests


def get_set_cookie_headers(response):
    """Return every Set-Cookie header without merging multiple cookie values."""
    raw_headers = getattr(response.raw, "headers", None)
    if hasattr(raw_headers, "getlist"):
        return list(raw_headers.getlist("Set-Cookie"))
    if hasattr(raw_headers, "get_all"):
        return list(raw_headers.get_all("Set-Cookie") or [])
    return []


def error_result(target_url, message):
    """Return a consistent result when an HTTP request cannot be completed."""
    return {
        "status": "error",
        "message": message,
        "requested_url": target_url,
        "final_url": None,
        "status_code": None,
        "response_time_ms": None,
        "content_type": None,
        "server": None,
        "redirect_count": 0,
        "response_headers": {},
        "set_cookie_headers": [],
    }


def analyze_http(target_url):
    """Request a validated URL and return basic HTTP response information."""
    try:
        response = requests.get(target_url, allow_redirects=True, timeout=10)
    except requests.exceptions.SSLError:
        return error_result(target_url, "SSL/TLS certificate verification failed.")
    except requests.exceptions.Timeout:
        return error_result(target_url, "The HTTP request timed out after 10 seconds.")
    except requests.exceptions.ConnectionError:
        return error_result(target_url, "Could not connect to the target URL.")
    except (
        requests.exceptions.InvalidURL,
        requests.exceptions.MissingSchema,
        requests.exceptions.InvalidSchema,
    ):
        return error_result(target_url, "The target URL is invalid.")
    except requests.exceptions.RequestException as error:
        return error_result(target_url, f"HTTP request failed: {error}")

    return {
        "status": "completed",
        "message": "HTTP analysis completed.",
        "requested_url": target_url,
        "final_url": response.url,
        "status_code": response.status_code,
        "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
        "content_type": response.headers.get("Content-Type"),
        "server": response.headers.get("Server"),
        "redirect_count": len(response.history),
        "response_headers": dict(response.headers),
        "set_cookie_headers": get_set_cookie_headers(response),
    }
