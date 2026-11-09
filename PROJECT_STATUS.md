# ORACLE project status

## Implemented

- Detached user-owned monitor daemon with `mrginu` CLI and Python packaging entry point.
- Proc start-time and command-identity validation, daemon `flock`, isolated managed process groups, stale record cleanup, graceful shutdown, and no boot autostart.
- CLI-managed loopback FastAPI and Vite services with service reuse checks and bounded rotating logs.
- Independent psutil monitor with configurable interval, first-pass process baseline, PID reuse detection, bounded identity memory, and no API-key requirement.
- SQLite WAL, busy timeout, event age/count retention, investigation cap, and bounded per-case chat history.
- Explainable local heuristic and evidence path kept independent from optional Groq inference.
- Configurable Groq OpenAI-compatible adapter for structured case review, provider connection test, and investigation-scoped chat. No model tool calls or command execution.
- Existing Gnani Prisma STT and Timbre TTS preserved as separate speech services.
- Responsive React dashboard with system/light/dark theme preference, compact case workflow, AI labels, evidence incompleteness, and chat.
- Arch Linux setup, CLI, privacy, and configuration instructions in README.

## Checks run

- `backend/.venv/bin/python -m pytest -q` from `backend`: 14 passed.
- `npm run build` from `frontend`: passed.
- `python3 -m compileall -q backend/oracle backend/tests`: passed.
- `./mrginu --help` and `./mrginu --status`: passed.
- `mrginu --dash` startup attempt: daemon launched, but backend readiness could not be verified because the managed sandbox denies loopback connections (`PermissionError: Operation not permitted`). The managed processes were stopped afterward. Browser launch and full service reuse were not verified in this environment.
- Editable package installation was attempted but pip could not resolve PyPI to install isolated build dependency `setuptools`; the standalone project launcher remains available.
- Groq behavior is covered with mocked requests. No live Groq or Gnani credential/service test was run.

## Configuration

- `GROQ_API_KEY` and optional `GROQ_MODEL` for LLM reasoning.
- `GNANI_API_KEY` for voice recognition and speech output.
- `ORACLE_POLL_INTERVAL`, `ORACLE_EVENT_RETENTION_DAYS`, `ORACLE_MAX_EVENTS`, `ORACLE_MAX_INVESTIGATIONS`, and optional `ORACLE_DB` for local operation.

## Known limitations

- Process snapshots can miss short-lived processes and connections hidden by permissions; this is not kernel-level/eBPF telemetry.
- The API is unauthenticated and must remain bound to `127.0.0.1`.
- `mrginu --dash` requires local loopback access, Node.js/npm dependencies, and an installed or project-local Python environment.
- Groq model availability depends on the account and may change; `GROQ_MODEL` is configurable.
- Chat context and the selected-case evidence bundle are sent to Groq only when a key is configured and the user submits a question or an investigation triggers a bounded review.
