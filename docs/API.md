# API Reference

Base URL: `http://localhost:8000`

All endpoints return `Content-Type: application/json` unless noted. Errors return `{"error": "<message>"}` with the appropriate HTTP status code.

## GET Endpoints

### `GET /`

Redirects to `/ohmypcap.html`.

---

### `GET /api/events`

Returns event data from Suricata's eve.json (via SQLite index or direct JSON parse).

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | No | current session | MD5 hash of a historical analysis |
| `type` | No | all | Filter by event type (`alert`, `dns`, `http`, `tls`, `flow`, `ftp`, `anomaly`, `fileinfo`) |
| `offset` | No | `0` | Pagination offset |
| `limit` | No | `1000` | Max events to return (capped at 5000) |

**Response:** Array of eve.json event objects.

**Example:**
```
GET /api/events?type=alert&limit=100
```

---

### `GET /api/stats`

Returns event-type counts for the current or specified analysis.

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | No | current session | MD5 hash of a historical analysis |

**Response:** Object mapping event type to count.

**Example:**
```json
{"alert": 42, "dns": 1500, "http": 380, "tls": 95, "flow": 2200}
```

---

### `GET /api/count`

Returns total event count, optionally filtered by type.

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | No | current session | MD5 hash of a historical analysis |
| `type` | No | all | Filter by event type |

**Response:** `{"count": <number>}`

---

### `GET /api/download-stream`

Carves a single TCP/UDP stream from the PCAP using `tcpdump` and returns it as a `.pcap` download.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `src` | Yes | Source IP address |
| `sport` | Yes | Source port |
| `dst` | Yes | Destination IP address |
| `dport` | Yes | Destination port |
| `md5` | No | MD5 hash of a historical analysis (defaults to current session) |

**Response:** `application/vnd.tcpdump.pcap` file download.

**Validation:** IP addresses and ports are validated before passing to tcpdump. Invalid values return `400`.

---

### `GET /api/ascii-stream`

Extracts ASCII payload from a TCP/UDP stream using `tshark`. Tries TCP first, falls back to UDP. Truncated to 100,000 characters.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `src` | Yes | Source IP address |
| `sport` | Yes | Source port |
| `dst` | Yes | Destination IP address |
| `dport` | Yes | Destination port |
| `md5` | No | MD5 hash of a historical analysis (defaults to current session) |

**Response:** `text/plain` — decoded ASCII transcript. Non-printable characters replaced with `.`.

---

### `GET /api/hexdump-stream`

Extracts per-packet hex dumps from a TCP/UDP stream using `tcpdump -X`. Truncated to 100,000 characters or 500 packets.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `src` | Yes | Source IP address |
| `sport` | Yes | Source port |
| `dst` | Yes | Destination IP address |
| `dport` | Yes | Destination port |
| `md5` | No | MD5 hash of a historical analysis (defaults to current session) |

**Response:** `application/json` — `{"packets": [{"header": "...", "lines": ["..."]}], "truncated": false}`.

**Validation:** IP addresses and ports are validated before passing to tcpdump. Invalid values return `400`.

---

### `GET /api/analyses`

Lists all previously-analyzed PCAPs.

**Response:** Array of `{"md5": "<hash>", "pcap": "<display name>"}` sorted alphabetically by name.

---

### `GET /api/load-analysis`

Loads a historical analysis by MD5, setting it as the current session.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `md5` | Yes | MD5 hash of the analysis to load |

**Response:**
```json
{"success": true, "md5": "<hash>", "pcap_name": "<filename>"}
```

**Errors:** `400` if MD5 is invalid or path is unsafe. `404` if analysis not found. `400` if eve.json exceeds size limit.

---

### `GET /api/delete-analysis`

Deletes a historical analysis (removes the entire MD5 directory).

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `md5` | Yes | MD5 hash of the analysis to delete |

**Response:** `{"success": true}`

---

### `GET /api/pcap-path`

Returns the filesystem path to the PCAP file in an MD5 directory.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `md5` | Yes | MD5 hash of the analysis |

**Response:** Plain text path. `404` if no PCAP found.

---

## POST Endpoints

### `POST /api/upload`

Uploads a PCAP file for analysis. Accepts multipart form data.

**Request:** Multipart form with a file field. Accepts `.pcap`, `.pcapng`, `.cap`, `.trace`, or `.zip`.

**Response (new file):**
```json
{"status": "processing", "md5": "<hash>"}
```

**Response (already analyzed):**
```json
{"status": "ready", "md5": "<hash>"}
```

**Processing flow:**
1. Validates file content (PCAP magic bytes or `.zip` extension)
2. Computes MD5 hash
3. If already analyzed (eve.json exists), returns `ready`
4. Otherwise saves file, spawns Suricata in background thread, returns `processing`
5. When Suricata finishes, eve.json is indexed into SQLite (`events.db`)

**Client should poll** `GET /api/check-status` with the returned MD5 to know when analysis is complete.

---

### `POST /api/load-url`

Downloads a PCAP from a URL and analyzes it.

**Request Body:**
```json
{"url": "https://example.com/capture.pcap"}
```

**Response:** Same as `/api/upload` — `{"status": "processing", "md5": "..."}` or `{"status": "ready", "md5": "..."}`.

**Special handling:**
- Password-protected zips from `malware-traffic-analysis.net` are auto-decrypted using the date-based password format (`infected_YYYYMMDD`)
- URL safety validation blocks localhost, private IPs, link-local, and non-HTTP schemes
- Hostname is resolved to verify the resolved IP is not private

**Errors:** `400` for invalid URL or SSRF attempt. `413` if file exceeds upload size limit.

---

### `POST /api/check-status`

Polls whether Suricata has finished processing an uploaded PCAP.

**Request Body:**
```json
{"md5": "<hash>"}
```

**Response:**
```json
{"status": "ready"}
```
or
```json
{"status": "processing"}
```

**Ready detection:** Checks that eve.json exists, is >10 bytes, and has at least one non-empty line.

---

## Error Codes

| Code | Meaning |
|---|---|
| `400` | Invalid input (bad IP, port, MD5, URL, path traversal) |
| `404` | Resource not found (no PCAP, no analysis, no packets) |
| `413` | File too large |
| `429` | Rate limited (currently always returns true — no-op) |
| `500` | Internal server error (generic message, no details leaked) |
