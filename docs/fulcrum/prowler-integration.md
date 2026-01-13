# Prowler Integration Architecture

## Data Ingestion
- Inputs: Prowler JSON and CSV files
- Parser: `fulcrum/prowler/parser.py` loads JSON lists or CSV rows
- Normalization: `fulcrum/prowler/normalize.py` produces canonical records

## Mapping Rules
- Mapping: `fulcrum/prowler/mapping.py` maps `check_id` to internal framework and default severity
- Extendable via table updates and versioning

## Reporting Outputs
- Markdown pages: `projects/security.md` with sections:
  - Firewall rules
  - Prowler Assessments (tables by project/control/severity/status)
- Machine outputs:
  - `data/security.json` (canonical records)
  - `data/security.csv` (flattened table)

## CLI Usage
- Security scanning and reporting:
  - Run scans: `fulcrum reports security run --provider gcp --projects p1 p2 --prowler-bin /usr/local/bin/prowler`
  - Ingest results: `fulcrum reports security ingest --prowler-json /path/results.json --prowler-csv /path/results.csv`
  - Format security report: `fulcrum reports security format --out-base /reports`
  - Validate: `fulcrum reports security validate --path /reports`
  - Scheduling guidance: `fulcrum schedule reports --cadence weekly`

## Validation
- Reports validated with `fulcrum validate-report`
- Ensures presence of Prowler section when inputs exist

## Troubleshooting
- Parser returns empty lists on invalid files
- Reporting degrades gracefully with warnings; outputs remain valid
- If Prowler is not installed: provide `--prowler-bin` or install Prowler; ingestion still works with pre-generated files

## Security
- No secrets in configuration files
- Respect least-privilege principles and redaction settings

## Versioning
- Maintain mapping and normalization schema versions
- Document changes in changelog and update validator rules if needed
