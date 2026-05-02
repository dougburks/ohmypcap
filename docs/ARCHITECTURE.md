# Architecture

## Overview

OhMyPCAP is a two-component application:

```
Browser ──HTTP──▶ ohmypcap.py (Python HTTP server, port 8000)
                      │
                      ├──▶ Suricata (subprocess, analyzes PCAP → eve.json)
                      ├──▶ SQLite (indexes eve.json → events.db)
                      ├──▶ tcpdump (carves individual streams)
                      └──▶ tshark (extracts ASCII transcripts)
```

All state is file-based under `~/ohmypcap-data/`. No database server, no external services.

## Server (ohmypcap.py)

A stdlib-only Python HTTP server (`http.server.SimpleHTTPRequestHandler`). Handles static file serving for `ohmypcap.html` and JSON API endpoints.

### Request Flow

1. **Upload/URL load** → validates input → saves PCAP → spawns Suricata subprocess → returns `processing`
2. **Client polls** `/api/check-status` until Suricata finishes
3. **Suricata callback** (background thread) → indexes eve.json into SQLite
4. **Client loads analysis** → UI fetches events via `/api/events`
5. **User interacts** → stream carving (`tcpdump`), ASCII extraction (`tshark`), filtering (client-side)

### Data Storage

```
~/ohmypcap-data/
  suricata/
    suricata.yaml          # Copied from /etc/suricata/, rule path rewritten
    rules/
      suricata.rules       # Downloaded by suricata-update (online) or copied from baked-in image (offline/air-gapped)
    disable.conf
  <md5>/
    <filename>.pcap        # Original PCAP
    eve.json               # Suricata JSON output (newline-delimited)
    events.db              # SQLite index (auto-created after analysis)
    name.txt               # Human-readable display name
```

### SQLite Schema

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    timestamp TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    app_proto TEXT,
    json_data TEXT          # Full original eve.json line
);
CREATE INDEX idx_event_type ON events(event_type);
CREATE INDEX idx_timestamp ON events(timestamp);
```

The `json_data` column stores the complete original event, allowing the server to return full eve.json objects without re-parsing the source file.

### Event Types

| Type | Description | Key fields |
|---|---|---|
| `alert` | Suricata rule matches | `alert.signature`, `alert.severity`, `alert.category`, `alert.rule` |
| `dns` | DNS queries/responses | `dns.rrname`, `dns.rrtype`, `dns.rcode` |
| `http` | HTTP requests | `http.http_method`, `http.url`, `http.http_content_type`, `http.status` |
| `tls` | TLS handshakes | `tls.sni`, `tls.version`, `tls.subject`, `tls.issuer` |
| `flow` | Network flow summaries | `flow.pkts_toserver`, `flow.pkts_toclient`, `flow.bytes_toserver`, `flow.bytes_toclient`, `flow.state` |
| `ftp` | FTP commands | `ftp.command` |
| `anomaly` | Protocol anomalies | `anomaly.message` |
| `fileinfo` | File transfers | `fileinfo.filename`, `fileinfo.filetype` |
| `stats` | Suricata internal stats | (excluded from display) |

## UI (ohmypcap.html)

A single-page application with all CSS and JavaScript inline. No external dependencies.

### UI States

```
Welcome Screen (no PCAP loaded)
  ├── URL input + file upload
  └── Previous analyses list

Analysis View (PCAP loaded)
  ├── Header (back button, name, path, date range)
  ├── Visualizations bar (Diagram toggle, Aggregation toggle)
  ├── Filter Bar (active filters as removable chips)
  ├── Stats Grid (clickable event-type cards, shows filtered/total counts when active)
  ├── Sankey Diagram (diagram mode — Source IP → Dest IP → Dest Port, reflects current filters)
  ├── Aggregations (aggregation mode — frequency counts per column)
  └── Data Sections (tabbed tables)
```

### JavaScript Architecture

**Global state:**
```js
let allEvents = [];          // Loaded for "All Events" tab
let sections = {};           // events per event type
let eventTypes = [];         // available types for current PCAP
let currentMd5 = '';         // current analysis MD5
let currentPcapName = '';    // display name
let currentFilters = {};     // {columnName: value} — global, flat
let advancedMode = false;    // advanced toggle state
let tabDataCache = {};       // cached event data per type
```

**Key function groups:**

| Group | Functions | Purpose |
|---|---|---|
| Navigation | `showWelcome()`, `loadAnalysis()`, `showTab()` | Screen/tab switching |
| Data Loading | `loadTabData()`, `loadFromUrl()`, `uploadPcap()`, `checkStatus()` | Fetch data from API |
| Rendering | `buildStats()`, `buildSections()`, `buildSection()`, `buildAllEvents()`, `buildRowForEvent()` | Build HTML |
| Aggregation | `buildAggregationTables()`, `buildAggregationTablesAll()`, `buildAggregationsSection()`, `buildAggregationsSectionAll()` | Frequency grids |
| Filtering | `applyFilter()`, `clearFilter()`, `clearAllFilters()`, `getFilteredEvents()` | Filter management |
| Streams | `downloadPcap()`, `loadAsciiTranscript()`, `toggleRow()` | Stream analysis |
| Utilities | `escapeHtml()`, `formatEvent()`, `extractValue()`, `extractAllValue()`, `getColumnsForType()` | Helpers |

### Column System

Each event type has its own column set. The "All Events" view uses a unified column set.

**Shared columns (all types):** Time, Protocol, Source IP, Source Port, Dest IP, Dest Port

**Per-type columns:** Alert, Category, Severity (alerts); Query, Type (DNS); Method, Host, URL, User-Agent, Status (HTTP); SNI / Host, Version, Subject, Issuer (TLS); Pkts →, Pkts ←, Bytes →, Bytes ←, State, Alerted (flows); Command (FTP); Message (anomaly); Filename (fileinfo)

**All-events columns:** Type (event type), Detail (type-specific summary)

### Filtering Design

Filters are **global** — `currentFilters` is a flat `{columnName: value}` object. When switching tabs, filters for columns that don't exist in the new view are silently skipped (the column lookup returns `-1` and the filter is ignored).

See [FILTERING.md](FILTERING.md) for full details.

## Security Model

- **Network:** Binds to `127.0.0.1` only
- **Input validation:** All user inputs (IP, port, MD5, URL, filename) validated before use in subprocess calls or filesystem operations
- **Path safety:** `is_safe_path()` prevents directory traversal via `os.path.realpath()` comparison
- **Content validation:** PCAP magic bytes checked on upload
- **URL safety:** Blocks localhost, private IPs, link-local; resolves hostname to verify resolved IP
- **Zip-slip:** Validates every extracted path stays within target directory
- **Error handling:** Generic "Internal server error" — no stack traces or internal paths leaked

## Testing

Two test files serve as executable specifications:

- **test_server.py** — Server-side: validation, security, API endpoints, SQLite, Suricata config
- **test_ui.py** — UI-side: HTML structure, CSS, JS functions, syntax, filtering, accessibility, performance

Tests are static analysis (string matching in source files) plus live server integration tests. No headless browser tests.
