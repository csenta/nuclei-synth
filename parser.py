"""
Offline heuristic parser for raw HTTP requests and PoC writeups.
Extracts method, path, headers, payload, and response matchers directly.
"""

import re
import yaml


def parse_raw_http(text: str) -> dict:
    """
    Heuristically extracts HTTP method, path, headers, body, and status code
    from raw HTTP transcript or PoC text.
    """
    result = {
        "method": "GET",
        "path": "/",
        "headers": {},
        "body": None,
        "match_status": 200,
        "match_words": [],
    }

    # Match HTTP Request line: e.g. POST /test.php?foo=bar HTTP/1.1
    req_match = re.search(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP\/", text, re.IGNORECASE)
    if req_match:
        result["method"] = req_match.group(1).upper()
        result["path"] = req_match.group(2)
    else:
        # Fallback to finding paths like /api/... or /admin/...
        path_match = re.search(r"(?:path|endpoint|url):\s*([/\w\-\.\?\=\%\&\:\+]+)", text, re.IGNORECASE)
        if path_match:
            result["path"] = path_match.group(1)

    # Match Content-Type header
    ct_match = re.search(r"Content-Type:\s*([^\r\n]+)", text, re.IGNORECASE)
    if ct_match:
        result["headers"]["Content-Type"] = ct_match.group(1).strip()

    # Match POST / PUT body immediately following request headers
    if result["method"] in ("POST", "PUT", "PATCH"):
        # Look for headers followed by double newline and body
        body_match = re.search(r"(?:Content-Length:[^\r\n]*|Content-Type:[^\r\n]*)\r?\n\r?\n([^\r\n].*?)(?=\r?\n\r?\n(?:Expected|HTTP|\Z))", text, re.DOTALL | re.IGNORECASE)
        if body_match:
            result["body"] = body_match.group(1).strip()
        else:
            parts = re.split(r"\r?\n\r?\n", text)
            if len(parts) > 1:
                for part in parts[1:]:
                    candidate = part.strip()
                    if candidate and not candidate.startswith("HTTP/") and not candidate.startswith("Severity:"):
                        result["body"] = candidate
                        break

    # Match expected HTTP response status code
    status_match = re.search(r"HTTP\/\d(?:\.\d)?\s+(\d{3})", text)
    if status_match:
        result["match_status"] = int(status_match.group(1))

    # Match distinct response markers or strings
    resp_match = re.search(r"(?:Expected Response|Response Body|Response)[\s\S]*?\r?\n\r?\n([^\r\n]+)", text, re.IGNORECASE)
    if resp_match:
        marker = resp_match.group(1).strip()
        if marker and not marker.startswith("HTTP/"):
            result["match_words"].append(marker[:80])

    return result


def generate_heuristic_template(advisory_text: str, template_id: str = "cve-synthesized-poc") -> str:
    """
    Generates a valid Nuclei v3 YAML template using deterministic heuristic extraction.
    """
    parsed = parse_raw_http(advisory_text)
    cve_match = re.search(r"CVE-\d{4}-\d+", advisory_text, re.IGNORECASE)
    if cve_match:
        template_id = cve_match.group(0).lower()

    # Determine severity
    severity = "medium"
    if re.search(r"critical", advisory_text, re.IGNORECASE):
        severity = "critical"
    elif re.search(r"high", advisory_text, re.IGNORECASE):
        severity = "high"
    elif re.search(r"low", advisory_text, re.IGNORECASE):
        severity = "low"

    full_path = parsed["path"]
    if not full_path.startswith("/"):
        full_path = "/" + full_path

    template_dict = {
        "id": template_id,
        "info": {
            "name": f"Vulnerability Check - {template_id.upper()}",
            "author": "nucleisynth",
            "severity": severity,
            "description": f"Automated vulnerability detection template synthesized for {template_id.upper()}.",
            "tags": "cve,synthesized,vuln",
        },
        "http": [
            {
                "method": parsed["method"],
                "path": [f"{{{{BaseURL}}}}{full_path}"],
                "matchers-condition": "and",
                "matchers": [
                    {
                        "type": "status",
                        "status": [parsed["match_status"]],
                    }
                ],
            }
        ],
    }

    if parsed["headers"]:
        template_dict["http"][0]["headers"] = parsed["headers"]

    if parsed["body"]:
        template_dict["http"][0]["body"] = parsed["body"]

    if parsed["match_words"]:
        template_dict["http"][0]["matchers"].append({
            "type": "word",
            "part": "body",
            "words": parsed["match_words"],
        })

    return yaml.dump(template_dict, sort_keys=False, default_flow_style=False)
