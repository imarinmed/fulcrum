# Standardized Markdown Reporting

## Goals
- Consistent, readable Markdown across all reports
- Robust table formatting with escaping and alignment
- Validated structure, links, and timestamps

## Folder Structure
- Base: `reports/report-YYYYMMDD/`
  - `index.md`: overview and links
  - `metadata.json`: ISO 8601 UTC timestamp, version, sources, settings
  - `projects/`: category pages
    - `compute.md`, `data_storage.md`, `data_analytics.md`, `networking.md`, `security.md`, `serverless.md`, `virtual_machines.md`, `storage.md`, `buckets.md`

## Markdown Rules
- Headers: use H2 for section titles, H3 for subsections
- Tables:
  - Header row then separator row with alignment markers
  - Escape special characters: `| * _ [ ] \``
  - Replace newlines in cells with `<br/>`
- Links: relative paths within report folder; validate existence
- Code blocks: fenced with triple backticks

## Numbers & Units
- Bytes: human-readable units (KB/MB/GB/TB)
- Counts: thousands separators
- Percent: two decimal places
- Currency: `$` with two decimals

## Metadata
- `generated_at`: ISO 8601 UTC ending with `Z`
- `report_version`: semantic version of report schema
- `org_id`, `projects`: copied from settings
- `source_csv_paths`, `source_raw_paths`: absolute or project-relative paths
- `settings_snapshot`: full `fulcrum.toml` resolved values

## Validation
- Structure: required files and directories exist
- Tables: consistent column counts across header, separator, and rows
- Headers: at least one H2 on each page
- Links: all references resolve
- Timestamps: ISO 8601 UTC

## Extensibility
- Add new categories via the reporting registry
- Extend Markdown features in `fulcrum/core/markdown.py`
- Increment `report_version` on schema changes
