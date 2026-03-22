# Keraunos

Keraunos is a policy-controlled security assessment platform for authorized targets. It combines async run orchestration, a live dashboard, browser-assisted web testing, deterministic findings extraction, and report generation behind a FastAPI service.

It is built for practical assessment workflows rather than one-shot scanning. Runs are stateful, tool usage is policy-gated, and findings are curated from observed behavior instead of being a raw dump of subprocess output.

## Highlights

- Async assessment runs with persisted state and run history
- Live dashboard for target setup, mode selection, LLM provider control, and results review
- Web application testing with browser-assisted interaction, route discovery, session handling, and WebSocket support
- Deterministic findings extraction for web, transport, exposure, session, and authorization issues
- Policy engine for tool allowlists, scope enforcement, blocked flags, and timeout caps
- LLM-assisted planning with support for `Ollama` and `OpenRouter`
- HTML report generation with curated findings and route coverage
- Plugin-based tool wrappers for extending the execution layer

## Modes

- `system`: service and host-oriented assessment
- `webapp`: browser-backed web application assessment
- `ai_agent`: evaluation of LLM applications, prompt injection exposure, and data leakage paths

If you are testing a web application, use `webapp`. That mode is tuned to prioritize route coverage, application behavior, session-aware interaction, and web-focused findings over generic network noise.

## Architecture

- [`api.py`](api.py): FastAPI app, dashboard endpoints, LLM provider/model controls
- [`run_manager.py`](run_manager.py): async run scheduling and persistence
- [`orchestrator.py`](orchestrator.py): planning loop, policy enforcement, tool execution, fallback logic
- [`analysis_engine.py`](analysis_engine.py): deterministic findings extraction
- [`reporting.py`](reporting.py): report generation
- [`policy_engine.py`](policy_engine.py) and [`policy.json`](policy.json): safety and execution controls
- [`tool_wrappers/plugins`](tool_wrappers/plugins): pluggable wrapper implementations

## Requirements

- Python 3.11+
- Playwright Chromium for browser-backed web testing
- External tools depending on your workflow, such as `nmap`, `ffuf`, `gobuster`, `nikto`, `sqlmap`, or `nuclei`
- Optional: `Ollama` or `OpenRouter` if you want LLM-assisted planning/reporting

## Quick Start

1. Install Python dependencies:

```bash
pip install -r requirements.txt
playwright install chromium
```

2. Start the API:

```bash
uvicorn api:app --host 0.0.0.0 --port 8000
```

3. Open the dashboard:

```text
http://localhost:8000
```

4. Create a run from the UI, or use the API directly:

```bash
curl -X POST http://localhost:8000/runs \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"http://localhost:3000\",\"scope\":\"\",\"mode\":\"webapp\",\"max_steps\":12}"
```

5. Inspect run state:

```bash
curl http://localhost:8000/runs/<run_id>
```

6. Download the report:

```bash
curl http://localhost:8000/runs/<run_id>/report -o report.html
```

## Dashboard

The dashboard is the primary interface for normal usage. It supports:

- target and mode selection
- run launch, cancellation, and live progress tracking
- LLM provider switching between `OpenRouter` and `Ollama`
- dynamic Ollama model selection from locally available models
- results repository browsing with date and time stamps
- rendered HTML report viewing

## LLM Configuration

Keraunos supports both local and hosted LLM backends.

### OpenRouter

```bash
export KERAUNOS_LLM_PROVIDER=openrouter
export KERAUNOS_LLM_MODEL=stepfun/step-3.5-flash:free
export OPENROUTER_API_KEY=your-key
```

### Ollama

```bash
export KERAUNOS_LLM_PROVIDER=ollama
export KERAUNOS_LLM_MODEL=deepseek-r1:8b
export KERAUNOS_LLM_URL=http://localhost:11434
```

Role-specific overrides are supported:

```bash
export KERAUNOS_PLANNER_LLM_PROVIDER=ollama
export KERAUNOS_PLANNER_LLM_MODEL=deepseek-r1:8b
export KERAUNOS_REPORT_LLM_PROVIDER=openrouter
export KERAUNOS_REPORT_LLM_MODEL=stepfun/step-3.5-flash:free
```

## Docker

The container image includes the Python app, browser automation support, and the surrounding runtime needed for dashboard-driven testing.

1. Copy the environment template:

```bash
cp .env.example .env
```

2. Set your environment values in `.env`

3. Start the stack:

```bash
docker compose up --build
```

4. Open:

```text
http://localhost:8000
```

If the target application runs on your host machine, `host.docker.internal` is the expected bridge target from inside the container.

## CLI Usage

Run directly without the dashboard:

```bash
python main.py http://localhost:3000 --scope "" --max-steps 25 --policy-path policy.json
```

Disable confirmation prompts for automation:

```bash
python main.py http://localhost:3000 --no-confirmation
```

## API Authentication

Set `KERAUNOS_API_KEY` to enforce API authentication on all endpoints except `/health`.

```bash
export KERAUNOS_API_KEY="change-me"
```

Then send:

```text
X-API-Key: change-me
```

## Policy Controls

Execution is constrained by [`policy.json`](policy.json). Important controls include:

- `allowed_tools`
- `allowed_targets`
- `blocked_flags`
- `require_confirmation_for_risk`
- `max_tool_timeout_seconds`
- `tool_timeouts`

Timeouts are clamped before subprocess execution, and high-risk actions can be held behind confirmation depending on policy.

## Wordlist Registry

Register a custom local wordlist:

```bash
curl -X POST http://localhost:8000/wordlists \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"common\",\"path\":\"/absolute/path/to/wordlist.txt\",\"description\":\"custom list\"}"
```

List registered wordlists:

```bash
curl http://localhost:8000/wordlists
```

Delete a registry entry:

```bash
curl -X DELETE http://localhost:8000/wordlists/common
```

## Plugin Development

Add a new wrapper under [`tool_wrappers/plugins`](tool_wrappers/plugins):

```python
from tool_wrappers.base import ToolWrapper

class MyToolWrapper(ToolWrapper):
    tool_name = "my_tool"
    risk_level = "medium"

    def run(self, params: dict) -> dict:
        out = self._run_command(
            ["mytool", "--target", params["target"]],
            timeout=60,
            stop_callback=params.get("__stop_callback"),
        )
        return {"raw": out}
```

Plugins are discovered at runtime.

## Testing

Run the test suite with:

```bash
py -3 -m pytest -q
```

Note: on some Windows setups, `pytest` can fail due to temp directory permission issues rather than application logic. If that happens, point pytest at a writable temp base or run targeted sanity checks.

## Repository Files

The repository includes:

- [`LICENSE`](LICENSE)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- [`SECURITY.md`](SECURITY.md)
- [`.env.example`](.env.example)
- [`compose.yaml`](compose.yaml)

## Safety

Keraunos is for defensive use on systems you own or are explicitly authorized to assess. Do not use it against third-party infrastructure without permission.
