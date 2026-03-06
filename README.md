# Keraunos

Autonomous, policy-controlled pentesting orchestration service with async runs, plugin-based tools, deterministic findings extraction, and report generation.

## Features

- Async scan runs via FastAPI (`POST /runs`)
- Run lifecycle tracking with SQLite
- Cooperative cancellation with live subprocess termination
- Policy engine for tool allowlists, target scope, blocked flags, and timeout caps
- Plugin architecture for tool wrappers (`tool_wrappers/plugins`)
- Deterministic findings extraction from tool outputs
- HTML report generation per run
- Optional API key authentication

## Architecture

- `api.py`: HTTP API
- `run_manager.py`: async run scheduling and persistence
- `orchestrator.py`: decision loop, policy enforcement, tool execution
- `policy_engine.py` + `policy.json`: safety and execution controls
- `analysis_engine.py`: deterministic pentest findings
- `tool_wrappers/plugins/*`: pluggable wrappers (`nmap`, `http_probe`, `searchsploit`, `wpscan`, `sqlmap`)
- `reporting.py`: report generation

## Quick Start (Local)

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Start API:

```bash
uvicorn api:app --host 0.0.0.0 --port 8000
```

3. Create a run:

```bash
curl -X POST http://localhost:8000/runs \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"scanme.nmap.org\",\"scope\":\"\",\"max_steps\":8}"
```

4. Check run:

```bash
curl http://localhost:8000/runs/<run_id>
```

5. Cancel run:

```bash
curl -X POST http://localhost:8000/runs/<run_id>/cancel
```

6. Download report:

```bash
curl http://localhost:8000/runs/<run_id>/report -o report.html
```

## CLI Mode

```bash
python main.py <target> --scope "" --max-steps 25 --policy-path policy.json
```

Disable prompts for automation:

```bash
python main.py <target> --no-confirmation
```

## API Authentication

Set `KERAUNOS_API_KEY` to enforce auth on all endpoints except `/health`.

```bash
export KERAUNOS_API_KEY="change-me"
```

Then include:

```text
X-API-Key: change-me
```

## Policy Controls

Edit `policy.json`:

- `allowed_tools`
- `allowed_targets` (wildcards supported)
- `blocked_flags`
- `require_confirmation_for_risk`
- `max_tool_timeout_seconds`
- `tool_timeouts`

Tool timeouts are clamped by policy and enforced at subprocess level.

## Plugin Development

Add a new file under `tool_wrappers/plugins`:

```python
from tool_wrappers.base import ToolWrapper

class MyToolWrapper(ToolWrapper):
    tool_name = "my_tool"
    risk_level = "medium"

    def run(self, params: dict) -> dict:
        out = self._run_command(["mytool", "--target", params["target"]], timeout=60, stop_callback=params.get("__stop_callback"))
        return {"raw": out}
```

Plugins are auto-discovered at runtime.

## Pentesting Focus Improvements Implemented

- Multi-stage baseline sequence when LLM is unavailable:
  1. `nmap`
  2. `http_probe`
  3. `searchsploit`
  4. `wpscan`
  5. `sqlmap`
- Deterministic findings added for:
  - exposed services/ports
  - SQLi indicators
  - HTTP/TLS/header misconfigurations
  - insecure WordPress/plugin indicators
  - public exploit reference correlation counts
- Findings are deduplicated and persisted into run state/report.

## Safety Boundary

This repository currently supports **passive/assessment-oriented** workflows.  
Exploit execution automation (for example via Metasploit modules) and brute-force wordlist attack setup are intentionally not included by default.

## Docker

```bash
docker build -t keraunos .
docker run --rm -p 8000:8000 keraunos
```

## Testing

```bash
py -3 -m pytest -q
```

## GitHub Readiness

Repository includes:

- `LICENSE`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SECURITY.md`
- `.github/workflows/ci.yml`
- `.gitignore`
- `.env.example`

## Safety

Authorized targets only. This project is for legal security assessment use in controlled environments.
