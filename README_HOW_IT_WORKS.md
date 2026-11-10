# ORACLE: How It Works

This guide explains what ORACLE does today, how its background monitor works, how to use the application, and what would be needed to make it more proactive. For installation details, see [README.md](README.md); for lower-level process boundaries, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Does ORACLE have a daemon?

**Yes.** ORACLE has a detached, user-owned monitoring daemon. It starts only when you explicitly run `mrginu` or `mrginu --dash`. It does not install a systemd unit or start automatically at boot.

The daemon is separate from the API server and dashboard:

- `mrginu` starts background monitoring and returns to the shell. It does not start the dashboard.
- `mrginu --dash` starts monitoring, starts the local API and dashboard if needed, and tries to open the browser.
- Closing the browser or restarting the API does not stop the daemon.
- The dashboard's **Start/Pause monitoring** control starts or stops the daemon.
- `mrginu --status` reports the daemon and managed services; `mrginu --stop` stops the daemon and only the services ORACLE started.

The daemon uses a lock and a PID record that includes Linux process start-time identity. This helps ORACLE recognize its own process safely and avoid confusing a reused PID for the original daemon.

## What does “watching processes” mean?

While running, the daemon asks `psutil` for process snapshots on a configurable interval: 3 seconds by default, with a 0.5 second minimum. On its first pass it records a baseline, so processes already running at startup are not treated as newly launched. Later passes identify new process instances using PID and process creation time.

For a newly observed process, ORACLE records available details such as its name, executable path, parent PID, and network endpoints visible at that snapshot. Separately, the daemon now records system CPU, memory, swap, root-disk use, disk I/O, network counters/throughput, and uptime every five seconds by default. It stores process resource samples every fifteen seconds for up to 64 processes with the highest observed CPU-plus-memory use; per-process samples include PID plus creation time, CPU, RSS, memory percent, threads, file descriptors where supported, and visible remote connections. These limits reduce overhead and bound database growth; processes outside the selected set are not represented in the per-process history.

Local heuristic rules still check process starts for a few suspicious patterns, including executables in temporary writable locations and temporary-path processes with network connections. Matching rules produce an explainable score and reason, not a malware verdict.

This is periodic user-space monitoring, **not continuous or exhaustive system telemetry**. It can miss processes that start and exit between polls, later changes made by a long-running process, and details hidden by Linux permissions. It does not currently track file changes, command-line activity, or every network connection over time. Resource charts become available only after monitoring has collected samples; ORACLE cannot reconstruct resource history from before it was started.

## What happens after a suspicious signal?

When a local rule gives an event a risk score of at least 35, ORACLE automatically creates a deterministic investigation and collects a limited evidence bundle using `psutil` (process details, visible network connections, and parent details). If a Groq key is configured, the investigation is queued for an optional AI review. The queue is bounded so a slow provider request does not hold up monitoring.

Resource detectors can also create alert records after enough history exists. Eligible medium-or-higher alerts link to a deterministic `resource_anomaly` event and one investigation; both IDs and the process creation time are stored. The daemon retries link work idempotently if it exits during processing. If the PID has since been reused, the new process is not attributed to the old alert. The alert inbox retains observed detector values and exposes the linked investigation.

Groq is used for investigation review and user-requested case chat. It receives an allowlisted bundle for that case; it does not receive a continuous stream of all processes, run tools, or execute commands. Its output is presented as model inference, separate from observed facts and local rules.

Gnani is used for speech features, not as the monitor's decision-maker:

- **Prisma STT** transcribes audio after the user deliberately starts recording. ORACLE displays the transcript and waits for a separate confirmation before routing a supported request. The microphone never starts automatically and recording stops after the short capture window.
- **Timbre TTS** reads a selected report on request and can optionally announce qualifying alerts. Alert speech is synthesized off the collector path, single-flight across API/daemon processes, rate-limited using provider `Retry-After`, and saved locally for replay.
- Desktop notifications run from the daemon through `notify-send`; they do not require a browser. Clicking an action opens a linked investigation when the dashboard is already available.

## Other features in the current application

- Local, explainable process heuristics work without Groq or Gnani credentials.
- Investigations include evidence, hypotheses, confidence, unknowns, and safe follow-up suggestions.
- Groq can provide a separate investigation assessment and answer questions about the selected case.
- Voice recording can submit an investigation command through Gnani Prisma.
- A report can be read aloud with Gnani Timbre.
- Events, investigations, and case chat are stored locally in SQLite, with age and count limits.
- Medium-or-higher resource alerts can automatically link to one investigation; the relationship is protected against duplicate worker execution and PID reuse.
- Linux desktop notifications and optional Timbre announcements run in separate daemon workers while the dashboard is closed. Timbre WAV audio is automatically played with `pw-play`, `aplay`, or `paplay`; a private temporary file is removed when playback ends.
- Delivery state is persisted with each alert. Queue saturation and interrupted daemon work are recovered from SQLite; failures receive bounded retries, and cooldowns are consumed only after notification delivery or audio playback succeeds.
- Alert replay serves audio generated for that alert; it does not make another provider request.
- Settings for collection, detection sensitivity, severity thresholds, notification/speech preferences, cooldown, and Groq reviews are saved through the backend in SQLite.
- The safe demo creates a clearly marked synthetic event; it does not launch a process or contact its example network address.
- The dashboard includes monitoring controls, process and investigation lists, settings, themes, and provider status.
- The Resource History section charts actual locally collected CPU, memory, network, and root-disk samples for supported time windows, and lists recent process resource samples.
- ORACLE does not kill processes, delete files, or automatically remediate a finding.

## How to use ORACLE

After installation and setup described in [README.md](README.md):

```bash
mrginu --dash       # Start monitoring and the local dashboard
mrginu --status     # Check daemon, API, and dashboard status
mrginu --stop       # Stop ORACLE-managed monitoring and services
```

In the dashboard, use **Run safe demo** to explore the investigation workflow with synthetic data. The Alert inbox **Send safe alert test** action creates a synthetic HIGH alert and sends it through the daemon's normal delivery workers. It never selects a PID, starts a process, or creates a network connection; it is marked as a test and limited to one per minute. Enable desktop notifications and spoken Timbre alerts in **Voice & Settings**; speech is disabled by default. To investigate a real process, enter a PID or use the supported investigation command. For voice commands, deliberately record, review the transcription, and click **Confirm voice command**. Choose **Read report** for interactive TTS.

Choose **Resources** to inspect recent system samples and the process samples collected since monitoring started.

Set optional credentials in the project-root `.env` file:

- `GROQ_API_KEY` enables AI investigation reviews and case chat; `GROQ_MODEL` can select a model.
- `GNANI_API_KEY` enables Prisma STT and Timbre TTS.
- Monitoring interval and SQLite retention limits can be adjusted with the `ORACLE_*` settings in `.env.example`.

The API and dashboard bind to loopback (`127.0.0.1`) and the API has no user authentication. Keep them local; do not expose the API port to a network.

## What ORACLE is trying to solve

ORACLE aims to make local Linux security signals easier to notice and investigate. It combines lightweight background process observation, transparent local rules, a saved evidence trail, and optional AI explanations in one local-first workflow. It is an investigation aid, not a complete endpoint detection system and not proof that a process is malicious.

## Resource history and alerting

The daemon now samples system resources every five seconds by default and up to 64 selected processes every fifteen seconds. The SQLite history is bounded by a 24-hour default retention period. The Resources view charts actual recorded CPU, memory, and network counters and can show sampled process history. Older history cannot be reconstructed retroactively.

The Alert inbox stores local, explainable statistical observations after a per-process baseline is available. CPU deviation, material RSS growth, and persistent newly observed endpoints are supported. Alerts include baseline evidence and can be acknowledged, snoozed, or resolved. Medium-and-higher alerts can link to an investigation and deterministic event. The daemon independently handles desktop notification and optional Timbre queues; high severity requires corroboration or very large memory growth. A high CPU value alone does not mean malware.

Still not implemented: process-tree anomaly detectors, restart-loop detection, a continuously open conversation, audio volume control from the daemon, and automatic remediation. Prisma remains user-initiated. Groq reviews only a linked case's allowlisted observations, never continuous telemetry. Desktop notifications depend on a session notification service such as `notify-send`; if it is absent, the alert stays in SQLite and the dashboard inbox.
