# NucleiSynth: Smart Nuclei Template Synthesizer

> **Status:** prototype. A personal security-research project, not a production product. Expect rough edges; issues and pull requests are welcome.

Automated pipeline that translates unstructured CVE advisories, bug bounty writeups, and HTTP PoCs into syntactically verified **Nuclei v3 YAML templates** with an autonomous self-correction loop.

---

## Features

- **Advisory to Template**: Ingests CVE reports, advisories, or raw HTTP transcripts and structures them into Nuclei v3 format.
- **Autonomous Repair Loop**: Evaluates generated templates against the local `nuclei -validate` engine. If validation fails, error output is fed back into the LLM to self-correct.
- **Provider Agnostic**: Works with Groq, OpenAI, Ollama (local models), DeepSeek, Anthropic, or any OpenAI-compatible API.
- **CLI & CI/CD Ready**: Can be used standalone or embedded in automated threat intelligence ingestion pipelines.

---

## Quick Start

### 1. Requirements
Ensure Python 3.10+ and Nuclei are available:
```bash
pip install -r requirements.txt
```

### 2. Run Template Validation
Test existing templates against the local engine:
```bash
python3 synthesizer.py --validate-only examples/sample_cve.txt
```

### 3. Generate a Nuclei Template from a CVE Advisory
Export your preferred LLM API key and run:
```bash
# Using Groq (default) or OpenAI / Ollama:
export SYNTH_API_KEY="your-api-key"
export SYNTH_MODEL="llama-3.3-70b-versatile"
# or for local Ollama:
# export SYNTH_BASE_URL="http://localhost:11434/v1"
# export SYNTH_MODEL="qwen2.5-coder:7b"

python3 synthesizer.py -i examples/sample_cve.txt -o cve-2024-4577.yaml
```

---

## Architecture

```
Advisory Input (Text/URL) 
       ↓
LLM Synthesis Engine (Prompt with Nuclei v3 Spec)
       ↓
YAML Syntax & Structural Checks
       ↓
Offline Engine Validation (`nuclei -validate`)
       ↓
[Pass] → Save YAML Template
[Fail] → Feedback Error to Repair Loop → Retry
```

## License

MIT. See [LICENSE](LICENSE).
