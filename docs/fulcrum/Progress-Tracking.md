# Fulcrum Progress Tracking

## Findings & Requirements
- Project-specific tracking with clear hierarchy and accessible design.
- Real-time updates at ≤5s refresh, with smooth animations and activity indicators.
- Accurate ETA and elapsed time; avoid premature 100% completion.
- Error states: stalled (yellow/orange), failed (red), recovery options.

## Implementation Methodology
- Generator emits per-project phase events to `master-report/tmp/progress.json`.
- CLI live-polls JSON and updates Rich progress bars per project and phase.
- ETA computed via elapsed and proportional remaining; minimum thresholds applied.
- TMP isolation: `TMPDIR` set to `master-report/tmp` to avoid system temp limits.

## File Index
- `fulcrum/core/progress.py`
  - Purpose: JSON state init/update for projects and phases.
  - Dependencies: `json`, `time`, `os`.
- `master-report/scripts/generate_catalog.py`
  - Purpose: Collect assets/IAM, write CSVs, raw evidence, and summary; emit progress events.
  - Dependencies: `yaml`, `gcloud`, `json`, `subprocess`.
- `fulcrum/cli.py`
  - Purpose: Report command; prepares config, launches generator, live-polls progress.json, renders per-project bars.
  - Dependencies: `rich`, `typer`, `subprocess`, `json`, `time`.
- `fulcrum/core/catalog.py`
  - Purpose: Orchestrator helpers; safe copy functions; TMP configuration.
  - Dependencies: `os`, `sys`, `subprocess`, `csv`, `shutil`.

## Testing Protocols & Results
- Unit: `progress.py` roundtrip reads/writes; phase updates compute ETA and elapsed.
- Integration: Generator run verifies `progress.json` updates and CSV/summary outputs.
- Validation: After run, required outputs exist and are non-empty.
- Manual: Observed live bars with ≤1s refresh; completion only after generator exits.

## Known Limitations
- Terminal UI cannot support hover tooltips; identifiers are displayed inline.
- Avatars/icons use emoji; font sizing depends on terminal.
- Trend graphs are not rendered; a future Textual widget can provide sparklines.

## Future Roadmap
- Textual dashboard with collapsible project sections and mini trend graphs.
- WebSocket server for remote monitoring; browser client with hover tooltips.
- Session persistence beyond JSON via sqlite for richer history.
- More phases: Networking, Kubernetes, Billing once integrated with upstream collectors.

## Color Scheme
- Resources: cyan; IAM: magenta; Networking: blue; Kubernetes: green; Billing: yellow; Validation: white.
- Stalled: orange; Failed: red.
