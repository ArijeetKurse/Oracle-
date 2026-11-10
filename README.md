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
- **Gnani speech (optional):** set `GNANI_API_KEY` for Prisma STT and Timbre TTS. TTS uses Gnani's REST inference endpoint at `https://api.vachana.ai/api/v1/tts/inference` with the `X-API-Key-ID` header, Timbre v2.5, and WAV output. Override only the TTS endpoint with `GNANI_TTS_URL` if needed; Prisma STT remains independently configured at `https://api.vachana.ai/stt/v3`. User-recorded voice is transcribed first and must be reviewed and confirmed before ORACLE routes it. Optional spoken alert summaries run in the daemon’s bounded worker queue and are disabled by default. Saved audio can be replayed from the alert inbox. Text investigation and local monitoring remain available without Gnani.
- **Monitoring and retention:** `ORACLE_POLL_INTERVAL` defaults to 3 seconds (minimum 0.5); system resource history samples every 5 seconds and selected process metrics every 15 seconds. Set `ORACLE_RESOURCE_INTERVAL`, `ORACLE_PROCESS_RESOURCE_INTERVAL`, `ORACLE_RESOURCE_RETENTION_HOURS` (24 by default), and `ORACLE_MAX_RESOURCE_PROCESSES` (64 by default) to tune this. Resource tables are added automatically when an existing SQLite database is opened. Event retention defaults to 30 days; `ORACLE_MAX_EVENTS` defaults to 10,000; `ORACLE_MAX_INVESTIGATIONS` defaults to 2,000. SQLite uses WAL mode and bounded chat history. Database location defaults to `backend/oracle.db`; set `ORACLE_DB` to override it.

The Resources view includes a local alert inbox. Detectors compare CPU with a median/MAD baseline, require material absolute and relative RSS growth, and require newly observed endpoints to persist. Alerts retain process creation identity and detector evidence. Medium and higher alerts can link to one deterministic event and investigation; the relationship is idempotent across retries and safe against PID reuse. High severity requires multiple corroborating resource/network signals or very large memory growth; an isolated CPU spike remains low. Alerts are review signals, not malware verdicts.

When the daemon is running, independent workers deliver threshold-qualified desktop notifications through `notify-send` and optionally synthesize and automatically play concise Timbre alert summaries. This works without a dashboard process. PipeWire `pw-play` is preferred, with `aplay` and `paplay` fallbacks. Playback uses a private temporary WAV and a child environment without provider credentials; it is removed after playback, and timeout cleanup terminates the player. SQLite tracks pending delivery and retries queue saturation, notification/device failures, and interrupted daemon work. Notification and speech cooldowns are applied only after successful delivery; a spoken alert is marked complete only after playback succeeds. Timbre uses the existing single-flight lease, honors `Retry-After`, and has bounded retries. At most 100 clips of up to 1 MB each are retained for replay. Configure controls in **Voice & Settings** or `/api/settings`; spoken alerts are disabled by default. Old alert rows and audio are bounded by retention and count limits.

Use **Send safe alert test** in the Alert inbox to create a synthetic HIGH alert. It has no PID, does not start or inspect a process, creates no network connection, and is visibly marked as a test. It follows the daemon delivery workers and is rate-limited to one synthetic test per minute. Desktop notification and speech still follow their enabled settings and severity thresholds. A local `pw-play`, `aplay`, or `paplay` executable and active desktop audio session are required for speaker playback.

For a dashboard-closed test, run `curl -sS -X POST http://127.0.0.1:8000/api/alerts/test` while the daemon is running, then check the returned alert ID at `http://127.0.0.1:8000/api/alerts/<ID>/delivery`. Speech status `played` means the audio player exited successfully; ORACLE cannot measure whether sound was physically audible at the speakers.

An investigation sends Groq a small allowlisted bundle for that case: process ID/name, a redacted executable path, heuristic reason and score, network endpoints, collected evidence, known unknowns, and—when linked to a resource alert—actual stored system/process samples and nearby events. No invented samples fill gaps. Usernames and command lines are excluded. Case chat sends only that case's bundle and up to four previous question/answer turns. Automatic reviews use a bounded queue and cannot block process polling. If Groq is unavailable, the deterministic local report remains available.

Groq output is displayed as AI inference, separately from local facts and heuristic results. It cannot invoke tools. Investigation evidence collection is fixed to allowlisted `psutil` calls for the selected process, parent, and network connections. No arbitrary shell execution, privilege escalation, destructive action, or automatic remediation is implemented.

Prisma transcription never executes the result directly. The dashboard shows the transcript and requires a separate confirmation click. Supported voice intents can open a selected investigation, explain an investigation or alert using its evidence when Groq is configured, or summarize an actual stored resource window. Transcripts cannot run shell commands.

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
