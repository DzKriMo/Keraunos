# Keraunos

Policy-controlled assessment service with async runs, live dashboarding, deterministic findings extraction, and report generation.

## Features

- Async scan runs via FastAPI (`POST /runs`)
- Run lifecycle tracking with SQLite
- Cooperative cancellation with live subprocess termination
- Policy engine for tool allowlists, target scope, blocked flags, and timeout caps
- Plugin architecture for tool wrappers (`tool_wrappers/plugins`)
- Deterministic findings extraction from tool outputs
- HTML report generation per run
- Optional API key authentication
- Safe evaluation modes for `system`, `webapp`, and `ai_agent`
- Live dashboard target preview, browser telemetry, and run-mode controls
- OpenRouter support with OpenAI-compatible model backends

## Architecture

- `api.py`: HTTP API
- `run_manager.py`: async run scheduling and persistence
- `orchestrator.py`: decision loop, policy enforcement, tool execution
- `policy_engine.py` + `policy.json`: safety and execution controls
- `analysis_engine.py`: deterministic pentest findings
- `tool_wrappers/plugins/*`: pluggable wrappers (`nmap`, `http_probe`, `searchsploit`, `metasploit_search`, `wpscan`, `sqlmap`)
- `wordlist_registry.py`: user-provided wordlist metadata store
- `reporting.py`: report generation

## Quick Start (Local)

1. Install dependencies:

```bash
pip install -r requirements.txt
playwright install chromium
```

2. Start API:

```bash
uvicorn api:app --host 0.0.0.0 --port 8000
```

3. Create a run:

```bash
curl -X POST http://localhost:8000/runs \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"http://localhost:3000\",\"scope\":\"\",\"mode\":\"webapp\",\"max_steps\":8}"
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

## Wordlist Registry (User-Provided Files)

Register local wordlist path:

```bash
curl -X POST http://localhost:8000/wordlists \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"common\",\"path\":\"/absolute/path/to/wordlist.txt\",\"description\":\"custom list\"}"
```

List registered wordlists:

```bash
curl http://localhost:8000/wordlists
```

Delete registry entry:

```bash
curl -X DELETE http://localhost:8000/wordlists/common
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

## LLM Provider Configuration

Keraunos now supports both local Ollama and OpenRouter.

OpenRouter example:

```bash
export KERAUNOS_LLM_PROVIDER=openrouter
export KERAUNOS_LLM_MODEL=stepfun/step-3.5-flash:free
export OPENROUTER_API_KEY=your-key
```

Role-specific overrides are also supported:

```bash
export KERAUNOS_PLANNER_LLM_PROVIDER=ollama
export KERAUNOS_PLANNER_LLM_MODEL=deepseek-r1:8b
export KERAUNOS_REPORT_LLM_PROVIDER=openrouter
export KERAUNOS_REPORT_LLM_MODEL=stepfun/step-3.5-flash:free
```

Ollama example:

```bash
export KERAUNOS_LLM_PROVIDER=ollama
export KERAUNOS_LLM_MODEL=deepseek-r1:8b
export KERAUNOS_LLM_URL=http://localhost:11434
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
  4. `metasploit_search` (search-only)
  5. `wpscan`
  6. `sqlmap`
- Deterministic findings added for:
  - exposed services/ports
  - SQLi indicators
  - HTTP/TLS/header misconfigurations
  - insecure WordPress/plugin indicators
  - public exploit reference correlation counts
- Findings are deduplicated and persisted into run state/report.

## Safety Boundary

This repository should be used for **defensive, authorized assessment workflows**.

Recommended modes:

- `system`: safe host review with allowlisted port and TLS checks
- `webapp`: safe route, header, cookie, and form review
- `webapp`: browser-assisted route, auth, file upload, WebSocket, and payload testing
- `ai_agent`: autonomous evaluation of LLM guardrails, prompt injection, and data leakage

The legacy orchestration path is still available for compatibility, but new dashboard controls default to the safer mode-based workflow.

## Docker

Keraunos now ships with a container build that includes the Python app, Kali tooling, Playwright, and Chromium for browser-driven web testing.

1. Create a local env file:

```bash
cp .env.example .env
```

2. Set at least:

```bash
OPENROUTER_API_KEY=your-key
KERAUNOS_LLM_PROVIDER=openrouter
KERAUNOS_LLM_MODEL=stepfun/step-3.5-flash:free
```

3. Start the stack:

```bash
docker compose up --build
```

4. Open:

```text
http://localhost:8000
```

The compose file persists run data under `./data`, publishes port `8000`, sets `host.docker.internal`, and gives Chromium extra shared memory for Playwright sessions.

If you prefer raw `docker run`, build and start it like this:

```bash
docker build -t keraunos .
docker run --rm -p 8000:8000 \
  --add-host=host.docker.internal:host-gateway \
  --shm-size=1g \
  --env-file .env \
  -v "$(pwd)/data:/app/data" \
  keraunos
```

`host.docker.internal` is still required when the target app is running on your host machine.

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
