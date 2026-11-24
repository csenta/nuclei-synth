"""
Validation module for Nuclei templates.
Performs YAML parsing, schema verification, and offline execution of 'nuclei -validate'.
"""

import os
import shutil
import subprocess
import tempfile
import yaml


def find_nuclei_binary() -> str | None:
    """Find the path to the nuclei executable."""
    return shutil.which("nuclei") or (
        "/home/emprogue/.local/bin/nuclei"
        if os.path.exists("/home/emprogue/.local/bin/nuclei")
        else None
    )


def validate_template(yaml_content: str) -> tuple[bool, str]:
    """
    Validates a Nuclei YAML template.
    Returns (True, "") on success, or (False, error_details) on failure.
    """
    # 1. Clean up markdown fences if model inadvertently included them
    cleaned = yaml_content.strip()
    if cleaned.startswith("```yaml"):
        cleaned = cleaned[len("```yaml"):].strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:].strip()
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()

    # 2. Syntax validation with PyYAML
    try:
        data = yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        return False, f"YAML Syntax Error:\n{exc}"

    if not isinstance(data, dict):
        return False, "Root YAML structure must be a dictionary / mapping."

    # 3. Essential Nuclei fields check
    if "id" not in data or not data["id"]:
        return False, "Missing required 'id' attribute in template root."

    if "info" not in data or not isinstance(data["info"], dict):
        return False, "Missing or invalid 'info' block in template root."

    info = data["info"]
    for required_info_key in ("name", "author", "severity"):
        if required_info_key not in info:
            return False, f"Missing required info attribute: '{required_info_key}'."

    valid_sections = ("http", "network", "dns", "headless", "ssl", "websocket", "whois", "code")
    if not any(sec in data for sec in valid_sections):
        return False, f"Template does not contain any protocol block (expected one of: {', '.join(valid_sections)})."

    # 4. Engine verification using Nuclei CLI
    nuclei_bin = find_nuclei_binary()
    if not nuclei_bin:
        # If nuclei binary is not present, YAML and basic structural checks suffice
        return True, ""

    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = os.path.join(tmpdir, "template.yaml")
        config_dir = os.path.join(tmpdir, "config")
        os.makedirs(config_dir, exist_ok=True)

        with open(template_path, "w", encoding="utf-8") as f:
            f.write(cleaned)

        env = os.environ.copy()
        env["XDG_CONFIG_HOME"] = config_dir

        cmd = [nuclei_bin, "-duc", "-validate", "-t", template_path]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            timeout=20,
        )

        output = proc.stdout or ""
        # Check for success marker or fatal errors
        if proc.returncode != 0 or "[FTL]" in output or "[ERR]" in output or "Could not validate" in output:
            # Extract actionable error lines
            error_lines = [
                line for line in output.splitlines()
                if any(tag in line for tag in ("[ERR]", "[FTL]", "error", "cause="))
            ]
            err_msg = "\n".join(error_lines) if error_lines else output.strip()
            return False, f"Nuclei Engine Error:\n{err_msg}"

    return True, ""
