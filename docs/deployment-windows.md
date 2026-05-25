# Deploying bumblebee on Windows

`bumblebee` is a one-shot binary with no built-in scheduler. On Windows,
the typical pattern is to run it from Task Scheduler, an MDM/endpoint
management job, or an EDR live-response command.

Cadence is the runner's choice. The profile determines what gets walked:

- `baseline` - bounded global/user package-manager and toolchain roots,
  editor extensions, browser extensions, and MCP config locations.
- `project` - configured developer/project roots such as `%USERPROFILE%\code`.
- `deep` - operator-supplied roots for incident response. Pair this with
  `--exposure-catalog` and, when useful, `--findings-only`.

## Baseline example

Run from PowerShell as the target user:

```powershell
.\bumblebee.exe scan `
  --profile baseline `
  --max-duration 5m `
  --output http `
  --http-url https://inventory.example.com/v1/ingest `
  --http-auth bearer `
  --http-token-env BUMBLEBEE_TOKEN `
  --device-id-env BUMBLEBEE_DEVICE_ID
```

Preview the default roots first:

```powershell
.\bumblebee.exe roots --profile baseline
```

The Windows baseline resolves existing roots under the current user's home,
including common Python, npm, pnpm, Yarn, nvm/fnm, editor extension, Claude
Desktop, Gemini, Cursor/Windsurf, Chromium-family browser, and Firefox-family
browser locations. Absent candidate paths are skipped.

## Project example

```powershell
.\bumblebee.exe scan `
  --profile project `
  --root "$HOME\code" `
  --root "$HOME\src"
```

`project` and `baseline` refuse broad home or filesystem roots. Use `deep`
when an incident-response sweep really does need a bare home directory:

```powershell
.\bumblebee.exe scan `
  --profile deep `
  --root "$HOME" `
  --exposure-catalog .\catalog.json `
  --findings-only `
  --max-duration 10m
```

## Multi-user hosts

`--all-users` is macOS-only. On Windows, schedule one per-user run for each
developer account, or enumerate explicit roots for a service-account run. This
keeps `endpoint.username` aligned with the account whose package inventory is
being reported.
