# State model

`bumblebee` is snapshot-only. Each run emits package records, optional
exposure findings, and one trailing `scan_summary`. It does not keep an
endpoint-side delta database or cache.

The receiver should derive current state from complete snapshots. This keeps
the endpoint simple and avoids bad deltas after missed runs, parser changes,
deleted projects, moved roots, or local state corruption.

## Promotion rule

Only promote records from a run after receiving a matching `scan_summary` with
`status=complete`.

Do not let package rows without a complete summary remove packages from current
state. Treat `partial`, `error`, timeout, and missing-summary runs as raw
evidence only; the previous complete run remains authoritative.

## Recommended tables

### `inventory_records_raw`

Append-only landing table for every received record.

Useful columns:

- `ingest_ts`
- `record_type`
- `record_id`
- `run_id`
- `endpoint_id`
- `profile`
- `schema_version`
- `scanner_version`
- `payload`

Keep the full JSON payload. Build narrower tables or views from this layer.

### `inventory_runs`

One row per `scan_summary`, keyed by `(endpoint_id, profile, run_id)`.

Useful columns:

- `endpoint_id`
- `profile`
- `run_id`
- `scan_time`
- `end_time`
- `status`
- `package_records_suppressed`
- `package_records_emitted`
- `findings_emitted`
- `findings_suppressed`
- `diagnostics_count`
- `http_batches_attempted`
- `http_batches_succeeded`
- `http_batches_failed`
- `http_last_status`
- `timed_out`
- `roots`
- `schema_version`
- `scanner_version`

A run is promotable only when `status='complete'`.

The `http_batches_*` and `http_last_status` fields on `scan_summary`
reflect HTTP sink delivery observed before the summary itself is
emitted; the final flush that delivers the trailing `scan_summary`
batch is not included in its own counters. Receivers should treat the
arrival of a `status=complete` summary as the success signal for the
run, not the summary's own delivery stats.

### `inventory_current`

Derived from package rows in the latest complete run for each
`(endpoint_id, profile)`.

Use `baseline` and `project` as separate populations, then union them for
"what is currently installed on this endpoint." Do not use `deep` to retire
packages from current state; `deep` is an on-demand campaign scan and may cover
a different root set every time.

Example shape:

```sql
WITH latest AS (
  SELECT endpoint_id, profile, run_id
  FROM inventory_runs
  WHERE status = 'complete'
    AND profile IN ('baseline', 'project')
  QUALIFY ROW_NUMBER() OVER (
    PARTITION BY endpoint_id, profile
    ORDER BY end_time DESC
  ) = 1
)
SELECT r.*
FROM inventory_records_raw r
JOIN latest l USING (endpoint_id, profile, run_id)
WHERE r.record_type = 'package';
```

### `inventory_history`

Derived by comparing consecutive complete snapshots for the same
`(endpoint_id, profile)`.

Track at least:

- `endpoint_id`
- `profile`
- `ecosystem`
- `normalized_name`
- `version`
- `source_file`
- `first_seen`
- `last_seen`
- `present`

Never infer removal across profiles. A `baseline` run cannot remove a package
that was observed by `project`, and vice versa.

### `exposure_findings`

Derived from `record_type=finding` rows. This is the "are we exposed to this
package advisory?" surface.

Key fields:

- `endpoint_id`
- `profile`
- `run_id`
- `catalog_id`
- `severity`
- `ecosystem`
- `normalized_name`
- `version`
- `project_path`
- `source_file`
- `confidence`
- `evidence`

Findings are package-presence matches against an operator-supplied exposure
catalog. They are not network, process, file-hash, persistence, or dropped-file
IOCs.

## Record identity (`record_id`)

`record_id` is a content-addressed hash computed from a canonical tuple
per record type, not from the full JSON payload. It is stable across
runs, so a package observed twice in the same configuration produces
the same `record_id` even when `scanner_version` or `run_id` differ.

Tuple fields per record type:

- **package**: `profile`, `ecosystem`, `normalized_name`, `version`,
  `project_path`, `root_kind`, `install_scope`, `package_manager`,
  `source_type`, `source_file`, `direct_dependency`,
  `has_lifecycle_scripts`, `lifecycle_scripts`, `confidence`,
  `requested_spec`, `server_name`.
- **finding**: the matched package's identity plus `finding_type` and
  `catalog_id`.
- **scan_summary**: the run terminator payload.
- **diagnostic**: `(level, path, message)`.

Receivers can rely on `record_id` as a dedupe key within a single run
and as a stable join key across runs that observed the same identity
tuple. Each record type exposes a `StableID()` method in
`internal/model/model.go`; all four delegate to the unexported
`stableID` helper in the same file, which performs the canonical
hashing.

`run_id` is independent of `record_id`: it is a freshly generated
128-bit random value (hex-encoded) chosen once at scan start and
stamped on every record the run emits. It is not derived from
endpoint identity, scan inputs, or wall-clock time, so two runs on
the same host always have distinct `run_id` values.

## Endpoint identity

Prefer a stable `endpoint.device_id` supplied via `--device-id-env`. If that is
not available, derive `endpoint_id` from your device inventory. Hostname alone
is a last resort because it can change.

`endpoint.username` and `endpoint.uid` identify the scanner process. For
root-owned macOS `--all-users` runs, use `source_file` or `project_path` to
attribute a package to a specific user home.

## Operational edge cases

- **Empty complete run** — valid state. It means no parseable inventory for
  that profile.
- **Duplicate upload** — deduplicate by `(endpoint_id, run_id, record_id)`.
- **Late records** — make derivations rerunnable when a summary arrives.
- **Scanner upgrade** — watch for population-wide changes correlated with
  `scanner_version`; parser changes can alter normalized names or coverage.
- **Stale endpoints** — absence of recent complete runs means stale, not clean.
  Use a TTL matched to the profile cadence.
- **Changed roots** — package counts can shift when roots change. Use
  `scan_summary.roots` as the audit trail.
