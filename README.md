# ORACLE

ORACLE is a local-first Linux security monitor and investigation dashboard. It collects unprivileged `psutil` process snapshots, applies explainable local heuristics, and stores events and investigations in SQLite. A heuristic or AI response is not a malware verdict. ORACLE does not kill processes, remove files, or execute model-suggested commands.

## Arch Linux installation

Install Python, Node.js, npm, and Git using Arch packages:

```bash
sudo pacman -S --needed python python-pip nodejs npm git
git clone <your-oracle-repository> ~/Desktop/Oracle
cd ~/Desktop/Oracle
cp .env.example .env
python -m venv backend/.venv
backend/.venv/bin/python -m pip install -e 'backend[test]'
(cd frontend && npm ci)
```

No root privileges are needed to run ORACLE. The daemon starts only when you invoke `mrginu`; there is no systemd unit or boot autostart. To make the installed command available in a shell, activate its environment:

```bash
source ~/Desktop/Oracle/backend/.venv/bin/activate
```

The editable Python install creates `backend/.venv/bin/mrginu`. To invoke the project launcher as `mrginu` without activating the environment, link it into a directory on your `PATH`:

```bash
mkdir -p ~/.local/bin
ln -sf ~/Desktop/Oracle/mrginu ~/.local/bin/mrginu
```

## CLI

```text
mrginu              Start background monitoring; return to the shell
mrginu --dash       Start monitoring and needed local services, then open the dashboard
mrginu --status     Show daemon, monitor, backend, and dashboard status
mrginu --stop       Stop the daemon and only services started by mrginu
mrginu --help       Show command help
```

`mrginu` does not start a browser or web service. The dashboard command binds the API to `127.0.0.1:8000` and Vite to `127.0.0.1:5173`. It reuses a responding ORACLE service and refuses to take over an occupied port that does not identify as ORACLE. Processes it starts are tracked under `~/.local/state/oracle/` (or `$XDG_STATE_HOME/oracle/` when set) using a lock, PID, `/proc` process start time, and command identity. Logs rotate in that directory. Closing the browser does not stop monitoring.

The dashboard can also be started directly for development:

```bash
backend/.venv/bin/uvicorn oracle.main:app --app-dir backend --host 127.0.0.1 --port 8000
(cd frontend && npm run dev)
```

The daemon and API run as separate processes, so restarting the API or closing the browser does not stop the monitor. The **Start/Pause monitoring** dashboard control starts or stops only the daemon. `mrginu --stop` also stops the backend and frontend only when `mrginu --dash` started them.

## Configuration and credentials

Copy `.env.example` to `.env`. ORACLE reads it without shell expansion. Keep `.env` private; it is ignored by Git.

- **Groq reasoning (optional):** create a key at [console.groq.com/keys](https://console.groq.com/keys) and set `GROQ_API_KEY` in `.env`. Groq is used only for case review and chat; local detection and monitoring work without it. `GROQ_MODEL` is configurable and defaults to `openai/gpt-oss-120b`; check [Groq's supported model list](https://console.groq.com/docs/models) for current account availability. Requests use the [OpenAI-compatible API](https://console.groq.com/docs/openai) at `https://api.groq.com/openai/v1`.
- **Gnani speech (optional):** set `GNANI_API_KEY` for Prisma STT and Timbre TTS. TTS uses Gnani's REST inference endpoint at `https://api.vachana.ai/api/v1/tts/inference` with the `X-API-Key-ID` header, Timbre v2.5, and WAV output. Override only the TTS endpoint with `GNANI_TTS_URL` if Gnani provides a different endpoint for your account; Prisma STT remains configured independently at `https://api.vachana.ai/stt/v3`. STT transcribes voice; it does not reason. Groq handles reasoning. TTS reads an investigation report. Text investigation and chat remain available without Gnani.
- **Monitoring and retention:** `ORACLE_POLL_INTERVAL` defaults to 3 seconds (minimum 0.5); system resource history samples every 5 seconds and selected process metrics every 15 seconds. Set `ORACLE_RESOURCE_INTERVAL`, `ORACLE_PROCESS_RESOURCE_INTERVAL`, `ORACLE_RESOURCE_RETENTION_HOURS` (24 by default), and `ORACLE_MAX_RESOURCE_PROCESSES` (64 by default) to tune this. Resource tables are added automatically when an existing SQLite database is opened. Event retention defaults to 30 days; `ORACLE_MAX_EVENTS` defaults to 10,000; `ORACLE_MAX_INVESTIGATIONS` defaults to 2,000. SQLite uses WAL mode and bounded chat history. Database location defaults to `backend/oracle.db`; set `ORACLE_DB` to override it.

The Resources view includes a local alert inbox. Detectors wait for a minimum per-process history and compare CPU against a median/MAD baseline, require both absolute and relative resident-memory growth, and require a new endpoint to persist across multiple samples. Alerts store their baseline evidence, use process creation time alongside PID, and are deduplicated during a cooldown. They are review signals, not malware verdicts. Alert status can be filtered and changed in the dashboard. Configure detector defaults with `ORACLE_MINIMUM_OBSERVATION_MINUTES`, `ORACLE_MINIMUM_BASELINE_SAMPLES`, `ORACLE_CPU_SENSITIVITY`, `ORACLE_MEMORY_GROWTH_PERCENT`, and `ORACLE_ALERT_COOLDOWN_SECONDS`; live persisted overrides are available at the local `/api/settings` endpoint. Native desktop notifications, automatic alert investigations, proactive Timbre announcements, and voice follow-up are not implemented yet.

An investigation sends Groq a small allowlisted bundle for that case: process ID/name, a redacted executable path, heuristic reason and score, network endpoints, collected evidence, and known unknowns. Usernames and command lines are excluded. A case chat sends only that case's bundle and up to four previous question/answer turns. Conversations are stored locally with at most eight turns per investigation. No background or continuous LLM polling occurs. Automatic reviews use a small bounded queue and cannot block process polling. If no Groq key is configured or a request fails, the deterministic local report remains available and the UI shows the provider error.

Groq output is displayed as AI inference, separately from local facts and heuristic results. It cannot invoke tools. Investigation evidence collection is fixed to allowlisted `psutil` calls for the selected process, parent, and network connections. No arbitrary shell execution, privilege escalation, destructive action, or automatic remediation is implemented.

## Safe walkthrough

1. Run `mrginu --dash` and open Overview.
2. Choose **Run safe demo** to create a marked synthetic event. It does not start a process or contact its example endpoint.
3. Review the investigation evidence. If Groq is configured, its separate AI assessment will be labeled as inference; otherwise only local assessment is shown.
4. Use the investigation chat for questions about that case. A Groq key is required for AI answers.
5. For a live process, enter `Investigate PID <number>`. Exited or inaccessible processes are reported unavailable.

## Development checks

```bash
(cd backend && .venv/bin/python -m pytest -q)
(cd frontend && npm run build)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for process boundaries and data flow. The local API has no authentication and is intended for loopback use only; do not bind it to a network interface.
