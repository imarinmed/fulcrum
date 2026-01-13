# Fulcrum

Fulcrum is a polished, developer-friendly CLI and TUI for creating executive-grade catalogs of your GCP resources. It combines fast collection, clear validation, and engaging presentation for engineers and stakeholders alike.

## Highlights
- Executive report generation (Markdown, CSV, IAM matrix, raw evidence)
- Interactive Textual dashboard with responsive layout
- Data validation with color-coded feedback
- `uv`-based reproducible environments

## Quickstart
- Install deps:
  - `uv add typer textual rich pydantic structlog jinja2 pyyaml`
- Help:
  - `uv run python -m fulcrum --help`
- Generate a catalog:
  - `uv run python -m fulcrum report --org-id <ORG_ID> --projects <p1> <p2> --out-dir master-report`
- Validate:
  - `uv run python -m fulcrum validate --out-dir master-report`
- Dashboard:
  - `uv run python -m fulcrum dashboard --out-dir master-report`

## Configuration
- Create a TOML config: `uv run python -m fulcrum config init --config ./fulcrum.toml`
- Set org and projects:
  - `uv run python -m fulcrum config set-org-id 308776007368 --config ./fulcrum.toml`
  - `uv run python -m fulcrum config add-project marcablanca --config ./fulcrum.toml`
- Fulcrum reads config via `--config`, local `fulcrum.toml`, XDG, or `~/.config/fulcrum/fulcrum.toml`.

## Documentation
- Commands and usage: `docs/fulcrum/COMMANDS.md`
