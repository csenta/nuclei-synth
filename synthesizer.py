#!/usr/bin/env python3
"""
Smart Nuclei Template Synthesizer (NucleiSynth)
Autonomous pipeline translating CVE disclosures into validated Nuclei v3 templates.
"""

import argparse
import json
import os
import sys
import requests

from prompt import SYSTEM_PROMPT, REPAIR_PROMPT_TEMPLATE
from validator import validate_template
from parser import generate_heuristic_template


def query_llm(
    prompt: str,
    system_prompt: str = SYSTEM_PROMPT,
    base_url: str = "https://api.openai.com/v1",
    api_key: str = "",
    model: str = "gpt-4o",
) -> str:
    """Invokes OpenAI-compatible /chat/completions endpoint."""
    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}" if api_key else "",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def clean_yaml_output(text: str) -> str:
    """Strips markdown fences and extra whitespaces."""
    cleaned = text.strip()
    if cleaned.startswith("```yaml"):
        cleaned = cleaned[len("```yaml"):].strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:].strip()
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()
    return cleaned


def synthesize_template(
    advisory_text: str,
    base_url: str,
    api_key: str,
    model: str,
    max_retries: int = 3,
    offline_heuristic: bool = False,
) -> tuple[str, bool]:
    """
    Synthesizes and validates a Nuclei template with an autonomous repair loop.
    Falls back to offline heuristic extraction if no API key is configured.
    """
    if offline_heuristic or not api_key:
        print("[*] Performing offline heuristic template extraction...")
        current_yaml = generate_heuristic_template(advisory_text)
        print("[*] Validating synthesized heuristic template...")
        is_valid, error_msg = validate_template(current_yaml)
        if is_valid:
            print("[+] Heuristic template passed validation successfully!")
            return current_yaml, True
        else:
            print(f"[!] Validation warning: {error_msg}")
            return current_yaml, False

    print("[*] Generating initial Nuclei v3 template via LLM...")
    current_yaml = query_llm(
        prompt=f"Create a Nuclei v3 template based on this advisory:\n\n{advisory_text}",
        base_url=base_url,
        api_key=api_key,
        model=model,
    )
    current_yaml = clean_yaml_output(current_yaml)

    for attempt in range(1, max_retries + 1):
        print(f"[*] Validating template (Attempt {attempt}/{max_retries})...")
        is_valid, error_msg = validate_template(current_yaml)

        if is_valid:
            print("[+] Template passed validation successfully!")
            return current_yaml, True

        print(f"[!] Validation failed:\n{error_msg}")
        if attempt < max_retries:
            print("[*] Invoking self-correction loop...")
            repair_prompt = REPAIR_PROMPT_TEMPLATE.format(
                error_message=error_msg,
                previous_yaml=current_yaml,
            )
            current_yaml = query_llm(
                prompt=repair_prompt,
                base_url=base_url,
                api_key=api_key,
                model=model,
            )
            current_yaml = clean_yaml_output(current_yaml)

    print("[-] Maximum self-correction retries reached without a clean validation.")
    return current_yaml, False


def main():
    parser = argparse.ArgumentParser(
        description="NucleiSynth: Convert CVE writeups into validated Nuclei v3 YAML templates."
    )
    parser.add_argument(
        "-i", "--input", help="Path to file containing CVE advisory, or raw advisory text."
    )
    parser.add_argument(
        "-o", "--out", help="Output YAML file path (default: stdout or template ID name)."
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("SYNTH_MODEL", "llama-3.3-70b-versatile"),
        help="LLM model name (default: llama-3.3-70b-versatile or gpt-4o).",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SYNTH_BASE_URL", "https://api.groq.com/openai/v1"),
        help="OpenAI-compatible API base URL (default: https://api.groq.com/openai/v1).",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("SYNTH_API_KEY", os.environ.get("OPENAI_API_KEY", "")),
        help="API Key for the LLM endpoint.",
    )
    parser.add_argument(
        "--heuristic",
        action="store_true",
        help="Use deterministic offline parser without contacting an LLM.",
    )
    parser.add_argument(
        "--validate-only",
        help="Validate an existing Nuclei YAML template without synthesis.",
    )

    args = parser.parse_args()

    # Standalone validation mode
    if args.validate_only:
        with open(args.validate_only, "r", encoding="utf-8") as f:
            content = f.read()
        valid, err = validate_template(content)
        if valid:
            print(f"[+] '{args.validate_only}' is a VALID Nuclei template.")
            sys.exit(0)
        else:
            print(f"[-] '{args.validate_only}' is INVALID:\n{err}")
            sys.exit(1)

    # Ingest advisory text
    advisory_text = ""
    if args.input:
        if os.path.isfile(args.input):
            with open(args.input, "r", encoding="utf-8") as f:
                advisory_text = f.read()
        else:
            advisory_text = args.input
    elif not sys.stdin.isatty():
        advisory_text = sys.stdin.read()
    else:
        parser.print_help()
        sys.exit(1)

    if not advisory_text.strip():
        print("[!] Error: No advisory input provided.")
        sys.exit(1)

    template_yaml, success = synthesize_template(
        advisory_text=advisory_text,
        base_url=args.base_url,
        api_key=args.api_key,
        model=args.model,
        offline_heuristic=args.heuristic,
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(template_yaml)
        print(f"[+] Saved template to: {args.out}")
    else:
        print("\n--- GENERATED TEMPLATE ---")
        print(template_yaml)


if __name__ == "__main__":
    main()
