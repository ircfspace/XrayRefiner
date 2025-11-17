# XraySubRefiner

A small Go utility to normalize multiple Xray subscription sources and generate four output lists for each subscription key.

It runs locally or as a GitHub Actions workflow (hourly + manual dispatch).

## Highlights

- Read multiple subscription URLs from `config.yaml` (each with a friendly `key`).
- Detect and decode Base64 subscriptions automatically.
- Filter by allowed schemes only (e.g., `vless`, `vmess`, `ss`, `trojan`).
- Ignore comments and blank lines.
- Remove duplicates.
- Robust Windows-friendly atomic file writing (temp + retry).
- Outputs have **no file extension** and are **Base64-encoded**.
- Lite list is always the **last 100** items (or fewer if the list is shorter).

## How it works (pipeline)

1. Fetch each subscription URL.
2. Detect if the entire payload is Base64; if so, decode it.
3. Split into individual URIs, ignore comments/blank lines.
4. Keep only URIs that start with allowed schemes.
5. Normalize schemes to lowercase and deduplicate.
6. Produce four outputs per key:
   - **normal**: all valid entries, sorted, **Base64-encoded**.
   - **lite**: last 100 items (newest at end), **in original order**, **Base64-encoded**.
   - **IPv4**: all valid IPv4 entries, sorted, Base64-encoded.
   - **IPv6**: all valid IPv6 entries, sorted, Base64-encoded.

## Requirements

- **Go 1.22+**

## Local usage

### Run without build

```bash
go run ./cmd/xraysubrefiner -config config.yaml -out export
```

### Build and run

```bash
go build -o xsr ./cmd/xraysubrefiner
./xsr -config config.yaml -out export
```

On Windows PowerShell:

```powershell
go build -o xsr.exe .\cmd\xraysubrefiner
.\xsr.exe -config config.yaml -out export
```

### Useful flags

- HTTP timeout (default `20s`):

```bash
./xsr -config config.yaml -out export -timeout 30s
```

## Outputs

After a successful run, you will see:

```
export/<key>/normal   # Base64-encoded, sorted list of all filtered entries
export/<key>/lite     # Base64-encoded, last 100 entries of the above (order preserved)
```

> Note: Both files are **Base64**. Decode them to see the raw URIs.

## GitHub Actions

A ready-to-use workflow is included at `.github/workflows/normalize.yml`:

- Triggers every hour (`cron: "0 * * * *"`).
- Can be run manually via `workflow_dispatch`.
- Builds the tool, runs it, and commits any changes to `export/` back to the repo.

## Troubleshooting

- **`missing go.sum entry`**: run `go mod tidy` once.
- **Windows file in use (rename error)**: the tool uses temp + retry, but if a file viewer/AV holds the file, close the viewer, exclude the folder in AV, or change the output dir temporarily (e.g., `-out export_new`).
- **No output**: ensure your subscriptions actually contain URIs with allowed schemes after decoding.
- **Huge outputs**: normal list is full by design; the lite list is capped to the last 100 entries.
