# ORACLE architecture

```text
explicit `mrginu` invocation
  ├── detached monitor daemon (flock + proc start-time identity)
  │     └── bounded psutil polling → local resource sampler + local heuristic rules → SQLite
  │            └── event ≥ threshold → deterministic investigation
  │                   └── bounded queue → optional Groq review
  └── optional `mrginu --dash`
        ├── FastAPI (127.0.0.1:8000) → SQLite and Groq case chat/review
        └── Vite (127.0.0.1:5173) → React dashboard
              └── explicit audio upload / report playback → Gnani STT/TTS
```

The monitoring daemon is separate from the backend and browser. Its first pass establishes a process baseline; subsequent process identities use `(PID, create_time)` to avoid treating reused PIDs as the same process. It keeps a bounded in-memory identity map and polls at the configured interval. A local resource sampler writes system counters every five seconds by default and a bounded set of process metrics every fifteen seconds. System and process resource samples are stored in additive SQLite tables with timestamp/identity indexes and configurable time retention. Resource reads are served by the loopback API for the dashboard timeline. Heuristics are local and run before optional model analysis. Automatic model reviews have a bounded queue; the collector never waits on a network request.

SQLite connections use WAL, a busy timeout, indexes, age-based retention, and event/investigation caps. Chat context is stored per investigation, limited to eight turns, and pruned with old investigations. The CLI stores its lock and managed process records in the user's state directory. PID records include Linux `/proc` start time and a command marker; services started by the CLI use isolated process groups. No boot unit is installed.

Investigation inspection is fixed to `psutil` process details, parent details, and network endpoints. The reasoning adapter sends an allowlisted case bundle to Groq; it omits usernames and command lines and redacts usernames embedded in `/home/...` paths. Case chat includes only the selected investigation and four previous turns. No model tool calls or shell execution are enabled. AI report fields are explicitly inference; local heuristic output and collected facts are separate. Groq failures do not replace or invalidate the deterministic report.

`detection.py` evaluates process samples after they are persisted. It waits for the configured baseline count and observation window, compares CPU with a median/MAD-derived bound, requires substantial absolute and relative RSS growth, and requires a newly observed endpoint to persist across multiple samples. It records observed values and baseline details in an additive `alerts` table, deduplicated by detector and process identity during a configured cooldown. Alert state transitions are served by `/api/alerts`; dashboard filters and actions operate on those local records. Alerts are statistical observations, not security verdicts. Native desktop notification delivery, alert-to-investigation linking, proactive speech, and spoken-alert replay are not implemented.

Gnani is a separate speech integration: Prisma converts explicitly recorded audio to text, and Timbre converts report text to audio. It is not the reasoning provider. The API is unauthenticated and should remain loopback-only. The demo event is synthetic and remains marked as such.
