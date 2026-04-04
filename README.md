# OhMyPCAP

A standalone web application for analyzing PCAP files using Suricata. View security alerts, browse network metadata (DNS, HTTP, TLS, flows), extract ASCII transcripts, and carve individual streams — all from a single-page UI.

## Quick Start

Most folks will want to use our pre-built Docker image. If you prefer not to use our pre-built Docker image, then there are other options shown [below](#build-your-own-docker-image).

### Install Docker

If you don't already have Docker installed and are running [OhMyDebn](https://ohmydebn.org) or another Debian-based distro, then you can install and configure Docker like this:

```bash
sudo apt update && sudo apt -y install docker.io
sudo usermod -aG docker $USER
newgrp docker
```

### Use Docker to run OhMyPCAP

Once Docker is installed and configured, all you have to do is create a data directory and then run our OhMyPCAP Docker image with that data directory mounted as a volume:

```bash
mkdir -p ~/ohmypcap-data
docker run -v ~/ohmypcap-data:/data -p 8000:8000 ghcr.io/dougburks/ohmypcap:main
```

OhMyPCAP will update its NIDS rules and then prompt you to open http://localhost:8000/ohmypcap.html in your browser.

## Usage

### Analyze a PCAP

1. **Upload a file** — click "Choose File" and select a `.pcap`, `.pcapng`, `.cap`, or `.trace` file (or a `.zip` containing one)
2. **Load from URL** — paste a URL to a PCAP file and click "Load from URL". Password-protected zips from `malware-traffic-analysis.net` are auto-decrypted using the date-based password format
3. **Reopen a previous analysis** — previously analyzed PCAPs are listed on the welcome screen

### Navigate Results

After Suricata finishes processing, the UI displays:

- **Stats Grid** — clickable cards showing event counts by type (Alerts, DNS, HTTP, TLS, Flows, etc.)
- **Data Tables** — sortable tables with expandable detail rows showing full event JSON and ASCII transcripts
- **Aggregation Tables** — (Advanced mode) frequency counts for each column; click a value to filter
- **Filtering** — apply filters by clicking aggregation values; filter chips show active filters; filters persist across all tabs

### Advanced Mode

Toggle the "Advanced" switch in the upper right to enable:
- Aggregation tables showing top-10 values per column
- Inline filter bar with filter chips
- Cross-tab filter persistence

### Stream Analysis

Click any row in a data table to expand it, then:
- **ASCII Transcript** — view decoded TCP/UDP payload as readable text
- **Download PCAP** — carve that specific stream into a standalone `.pcap` file

## Data Storage

All analyzed PCAPs are stored in `~/ohmypcap-data/`. Each analysis gets a subdirectory named by its MD5 hash containing:

```
~/ohmypcap-data/<md5>/
  <original-filename>.pcap   # The uploaded PCAP
  eve.json                   # Suricata's JSON output
  events.db                  # SQLite index (auto-created after analysis)
  name.txt                   # Human-readable display name
```

## Build Your Own Docker Image

If you prefer to build your own Docker image, you can clone this github repo and then build the image:

```bash
git clone https://github.com/dougburks/ohmypcap
cd ohmypcap
docker build -t ohmypcap .
mkdir -p ~/ohmypcap-data
docker run -v ~/ohmypcap-data:/data -p 8000:8000 ohmypcap
```

Then open http://localhost:8000/ohmypcap.html in your browser.

## Running without Docker

If you prefer to run without docker, then you will need these prerequisites:

- **Python 3** (stdlib only — no pip packages required)
- **Suricata** — for PCAP analysis and rule-based alerting
- **suricata-update** — for downloading/updating Suricata rules
- **tcpdump** — for stream carving (`/api/download-stream`)
- **tshark** — for ASCII transcript extraction (`/api/ascii-stream`)

Once you have the preqequisites, then you can clone this github repo and run the server:
```bash
python3 ohmypcap.py
```

Then open http://localhost:8000/ohmypcap.html in your browser.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `~/ohmypcap-data` | Directory for analyzed PCAPs and Suricata config |
| `BIND_ADDRESS` | `127.0.0.1` | Address to bind the HTTP server to |
| `PORT` | `8000` | HTTP server port |


## Configuration

| Constant | Default | Description |
|---|---|---|
| `PORT` | `8000` | HTTP server port |
| `BASE_DIR` | `~/ohmypcap-data` | Root directory for analyzed PCAPs |
| `MAX_UPLOAD_SIZE` | `1000 MB` | Maximum PCAP upload size |
| `MAX_EVE_SIZE` | `1000 MB` | Maximum eve.json size |
| `MAX_TRANSCRIPT_SIZE` | `100,000 chars` | Maximum ASCII transcript length |

Suricata config is auto-generated from `/etc/suricata/` on first run. Rules are downloaded via `suricata-update` if not present.

## Security

- Binds to `127.0.0.1` only (no external access)
- No CORS wildcard
- Input validation on all endpoints (IP, port, MD5, path traversal)
- PCAP magic byte validation (rejects non-PCAP uploads)
- URL safety checks (blocks localhost, private IPs, resolves hostname)
- Zip-slip prevention on archive extraction
- Generic error messages (no internal details leaked)

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a detailed overview of how the pieces fit together.

See [docs/API.md](docs/API.md) for the full API reference.

See [docs/FILTERING.md](docs/FILTERING.md) for details on the filtering system.

## Testing

```bash
# Server tests
python3 -m unittest test_server -v

# UI tests
python3 -m unittest test_ui -v

# All tests
python3 -m unittest discover -v
```

## License

See [LICENSE](LICENSE)
