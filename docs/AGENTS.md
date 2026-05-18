# AGENTS.md

This file contains agent-focused guidance for maintaining OhMyPCAP.

## Updating Vendored Dependencies

OhMyPCAP bundles D3 and d3-sankey in `static/` so the application works offline and builds remain deterministic.

### D3

To update to the latest version:

```bash
curl -sL "https://unpkg.com/d3@7/dist/d3.min.js" -o static/d3.min.js
curl -sL "https://unpkg.com/d3-sankey@0.12/dist/d3-sankey.min.js" -o static/d3-sankey.min.js
```

After updating, verify the files load correctly and run the test suite:

```bash
python3 -m unittest discover -v
```

If the copyright year changed, update `static/LICENSE` accordingly.

Check for D3 releases at https://github.com/d3/d3/releases.
Recommended cadence: every 6–12 months, or immediately if a security CVE is announced.

## Backend Architecture

OhMyPCAP's backend is split into domain modules. Do not add new logic directly to `ohmypcap.py` — place it in the appropriate module:

| Module | Add here if... |
|---|---|
| `validators.py` | Pure input validation (no HTTP, no I/O). IP/port checks, filename sanitization, URL safety, PCAP magic bytes, ZIP slip prevention. |
| `suricata.py` | Anything related to Suricata lifecycle: config setup, rule downloads, spawning subprocesses, processing locks, file extraction. |
| `yara_scanner.py` | YARA scanning: executable checks, rules download/setup, scanning extracted files, parsing output. |
| `db.py` | SQLite schema changes, new query functions, index optimization, bulk loading logic. |
| `models.py` | New Suricata event field extraction helpers (parsing JSON fields into typed values). |
| `config.py` | Application-wide constants: size limits, timeouts, thresholds. Adjust here for different deployments. |
| `ohmypcap.py` | Only HTTP handler methods, request/response formatting, and thin orchestration that calls other modules. |

### Handler Conventions

- Use `_send_json(data)` for all JSON responses, `_send_error(code, message)` for errors.
- Extract shared endpoint logic into helper methods on `Handler` (e.g., `_validate_stream_params`).
- Keep `do_GET` and `do_POST` as thin dispatchers via `GET_ROUTES` / `POST_ROUTES` class attributes.

### Frontend Structure

The frontend is split into three files under `static/`:

| File | Content |
|---|---|
| `ohmypcap.html` | HTML shell (no inline CSS/JS) |
| `static/ohmypcap.css` | All styles |
| `static/ohmypcap.js` | All JavaScript |

`ohmypcap.html` references them via `<link rel="stylesheet" href="static/ohmypcap.css">` and `<script src="static/ohmypcap.js"></script>`.

When updating styles or frontend logic, edit the appropriate split file. Keep `ohmypcap.html` free of inline `<style>` and `<script>` blocks.

## README Maintenance

When adding, removing, or renaming sections in `README.md`, always update the **Table of Contents** at the top of the file. GitHub auto-generates anchor IDs from heading text (lowercased, spaces→hyphens, special chars stripped). Duplicate heading names get `-1`, `-2`, etc. suffixes.
