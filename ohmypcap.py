#!/usr/bin/env python3
import http.server
import socketserver
import json
import os
import subprocess
import hashlib
from urllib.parse import urlparse, parse_qs
import urllib.request
import zipfile
import re
import tempfile
import time
import shutil
import sys
import threading

from db import (
    get_event_count_sqlite, get_event_types_sqlite, query_events_sqlite,
    create_file_analysis_db,
)
from validators import (
    validate_ip, validate_port, sanitize_filename, is_safe_path,
    validate_url_safety, validate_zip_extraction, validate_pcap_content
)
from suricata import (
    REQUIRED_EXECUTABLES, check_executables, has_internet_access,
    setup_suricata_config, spawn_suricata, _set_error
)
from yara_scanner import check_yara_executable, setup_yara_rules, scan_single_file
import config

VERSION = '4.0.0'
PORT = int(os.environ.get('PORT', 8000))
BIND_ADDRESS = os.environ.get('BIND_ADDRESS', '127.0.0.1')
DATA_DIR = os.environ.get('DATA_DIR', os.path.expanduser('~/ohmypcap-data'))
# Re-export size limits for backward compatibility
MAX_TRANSCRIPT_SIZE = config.MAX_TRANSCRIPT_SIZE
MAX_UPLOAD_SIZE = config.MAX_UPLOAD_SIZE
MAX_EVE_SIZE = config.MAX_EVE_SIZE
SURICATA_DIR = os.path.join(DATA_DIR, 'suricata')
SURICATA_RULES_DIR = os.path.join(SURICATA_DIR, 'rules')

PCAP_EXTENSIONS = ('.pcap', '.pcapng', '.cap', '.trace')
MD5_RE = re.compile(r'^[a-f0-9]{32}$')


def _attempt_zip_extract(zip_ref, extract_dir, passwords):
    """Extract ZIP contents, trying passwords if needed.

    Returns True on success, False if extraction failed.
    Raises ValueError on zip slip or size violations.
    """
    validate_zip_extraction(zip_ref, extract_dir)
    extracted = False
    try:
        zip_ref.extractall(extract_dir)
        extracted = True
    except RuntimeError:
        pass

    if not extracted and passwords:
        for pwd in passwords:
            try:
                zip_ref.extractall(extract_dir, pwd=pwd)
                extracted = True
                break
            except RuntimeError:
                continue

    return extracted


def extract_pcap_from_zip(zip_data, extract_dir, passwords=None):
    """Extract a PCAP file from zip_data into extract_dir.

    Returns (pcap_data, pcap_filename).
    Raises ValueError if extraction fails or no PCAP is found.
    """
    tmp_zip = os.path.join(extract_dir, 'archive.zip')
    with open(tmp_zip, 'wb') as f:
        f.write(zip_data)

    try:
        with zipfile.ZipFile(tmp_zip, 'r') as zip_ref:
            if not _attempt_zip_extract(zip_ref, extract_dir, passwords):
                raise ValueError('Password-protected ZIP could not be opened. Please extract the PCAP first.')

        pcap_files = [f for f in os.listdir(extract_dir) if f.endswith(PCAP_EXTENSIONS)]
        if not pcap_files:
            raise ValueError('No pcap file found in zip archive')

        extracted_pcap = os.path.join(extract_dir, pcap_files[0])
        with open(extracted_pcap, 'rb') as f:
            pcap_data = f.read()
        return pcap_data, pcap_files[0]
    finally:
        if os.path.exists(tmp_zip):
            os.unlink(tmp_zip)


def is_pcap_file(data):
    """Detect if file data is a PCAP or PCAPNG by magic bytes."""
    if len(data) < 4:
        return False
    magic = data[:4]
    # Classic PCAP (microsecond or nanosecond timestamps), either endianness
    if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                 b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
        return True
    # PCAPNG
    if magic == b'\x0a\x0d\x0d\x0a':
        return True
    return False


def _extract_zip_contents(zip_data, extract_dir, passwords=None):
    """Extract all contents from zip_data into extract_dir.

    Returns list of extracted file paths (excluding the temporary zip itself).
    Raises ValueError if extraction fails.
    """
    tmp_zip = os.path.join(extract_dir, 'archive.zip')
    with open(tmp_zip, 'wb') as f:
        f.write(zip_data)

    try:
        with zipfile.ZipFile(tmp_zip, 'r') as zip_ref:
            if not _attempt_zip_extract(zip_ref, extract_dir, passwords):
                raise ValueError('Password-protected ZIP could not be opened.')
    finally:
        if os.path.exists(tmp_zip):
            os.unlink(tmp_zip)

    # Return all extracted files, excluding hidden/metadata files
    files = []
    for f in os.listdir(extract_dir):
        if f.startswith('.') or f.startswith('__'):
            continue
        full_path = os.path.join(extract_dir, f)
        if os.path.isfile(full_path):
            files.append(full_path)
    return files


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _add_security_headers(self):
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;")

    def end_headers(self):
        self._add_security_headers()
        # Prevent browser caching of HTML and static assets so upgrades
        # are reflected immediately without manual cache clearing.
        if self.path.endswith('.html') or self.path.startswith('/static/'):
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
        super().end_headers()

    def _send_error(self, code, message):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode())

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _read_post_body(self, max_size):
        """Validate Content-Length and read POST body safely.

        Returns the raw body bytes, or None and sends an error response
        if validation fails.
        """
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length < 0 or content_length > max_size:
            self._send_error(400, 'Invalid Content-Length')
            return None
        return self.rfile.read(content_length)

    def _resolve_md5_dir(self, md5):
        """Validate MD5 format and resolve to a safe data directory path.

        Returns the absolute directory path, or raises ValueError with a
        descriptive message if validation fails.
        """
        if not md5:
            raise ValueError('md5 parameter required')
        if not MD5_RE.match(md5):
            raise ValueError('Invalid MD5')
        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            raise ValueError('Invalid path')
        return dir_path

    def _validate_stream_params(self, params):
        src = params.get('src', [''])[0]
        sport = params.get('sport', [''])[0]
        dst = params.get('dst', [''])[0]
        dport = params.get('dport', [''])[0]
        md5 = params.get('md5', [''])[0]

        if not md5:
            return None, 'md5 parameter required'
        if not (validate_ip(src) and validate_ip(dst) and validate_port(sport) and validate_port(dport)):
            return None, 'Invalid IP or port'
        if not MD5_RE.match(md5):
            return None, 'Invalid MD5'

        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            return None, 'Invalid path'

        pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)] if os.path.exists(dir_path) else []
        pcap = os.path.join(dir_path, pcap_files[0]) if pcap_files else None
        if not pcap:
            return None, 'No pcap file found'

        return {'pcap': pcap, 'src': src, 'sport': sport, 'dst': dst, 'dport': dport}, None

    GET_ROUTES = {
        '/api/events': 'handle_get_events',
        '/api/stats': 'handle_get_stats',
        '/api/count': 'handle_get_count',
        '/api/download-stream': 'handle_get_download_stream',
        '/api/ascii-stream': 'handle_get_ascii_stream',
        '/api/hexdump-stream': 'handle_get_hexdump_stream',
        '/api/analyses': 'handle_get_analyses',
        '/api/load-analysis': 'handle_get_load_analysis',
        '/api/delete-analysis': 'handle_get_delete_analysis',
        '/api/pcap-path': 'handle_get_pcap_path',
        '/api/version': 'handle_get_version',
    }

    POST_ROUTES = {
        '/api/upload': 'handle_post_upload',
        '/api/load-url': 'handle_post_load_url',
        '/api/check-status': 'handle_post_check_status',
        '/api/reanalyze': 'handle_post_reanalyze',
    }

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == '/':
            self.send_response(301)
            self.send_header('Location', '/ohmypcap.html')
            self.end_headers()
            return

        if path == '/favicon.ico':
            self.send_response(204)
            self.end_headers()
            return

        handler_name = self.GET_ROUTES.get(path)
        if handler_name:
            getattr(self, handler_name)(params)
        elif path == '/ohmypcap.html' or path.startswith('/static/'):
            super().do_GET()
        else:
            self._send_error(404, 'Not found')

    def do_POST(self):
        handler_name = self.POST_ROUTES.get(self.path)
        if handler_name:
            getattr(self, handler_name)()
        else:
            self._send_error(404, 'Not found')

    # ------------------------------------------------------------------
    # GET handlers
    # ------------------------------------------------------------------

    def handle_get_events(self, params):
        md5 = params.get('md5', [''])[0]
        if not md5:
            self._send_json([])
            return
        if not MD5_RE.match(md5):
            self._send_json([])
            return
        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_json([])
            return

        try:
            offset = int(params.get('offset', ['0'])[0])
            limit = int(params.get('limit', ['1000'])[0])
        except ValueError:
            self._send_json([])
            return

        offset = max(0, offset)
        limit = max(1, min(limit, config.MAX_QUERY_LIMIT))
        event_type = params.get('type', [''])[0] or None
        q_raw = params.get('q', [])
        q = [x.strip()[:200] for x in q_raw if x.strip()] or None

        db_file = os.path.join(dir_path, 'events.db')
        if os.path.exists(db_file):
            events = query_events_sqlite(db_file, event_type, offset, limit, q)
            self._send_json(events)
        else:
            self._send_json([])

    def handle_get_stats(self, params):
        md5 = params.get('md5', [''])[0]
        if not md5:
            self._send_json({'error': 'md5 parameter required'})
            return
        if not MD5_RE.match(md5):
            self._send_json({})
            return
        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_json({})
            return
        db_file = os.path.join(dir_path, 'events.db')
        q_raw = params.get('q', [])
        q = [x.strip()[:200] for x in q_raw if x.strip()] or None

        stats = {}
        if os.path.exists(db_file):
            stats = get_event_types_sqlite(db_file, q)
        self._send_json(stats)

    def handle_get_count(self, params):
        md5 = params.get('md5', [''])[0]
        if not md5:
            self._send_json({'error': 'md5 parameter required'})
            return
        event_type = params.get('type', [''])[0] or None
        q_raw = params.get('q', [])
        q = [x.strip()[:200] for x in q_raw if x.strip()] or None

        if not MD5_RE.match(md5):
            self._send_json({'count': 0})
            return
        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_json({'count': 0})
            return
        db_file = os.path.join(dir_path, 'events.db')

        if os.path.exists(db_file):
            count = get_event_count_sqlite(db_file, event_type, q)
        else:
            count = 0
        self._send_json({'count': count})

    def handle_get_download_stream(self, params):
        result, error = self._validate_stream_params(params)
        if error:
            self._send_error(400 if 'required' in error or 'Invalid' in error else 404, error)
            return

        pcap = result['pcap']
        src = result['src']
        sport = result['sport']
        dst = result['dst']
        dport = result['dport']

        try:
            proc = subprocess.run(
                ['tcpdump', '-r', pcap, '-w', '-', f"host {src} and host {dst} and port {sport} and port {dport}"],
                capture_output=True, timeout=config.STREAM_TIMEOUT_SECONDS
            )
            if proc.returncode == 0 and len(proc.stdout) > 0:
                filename = f"stream_{src}_{sport}_to_{dst}_{dport}.pcap"
                self.send_response(200)
                self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Content-Length', str(len(proc.stdout)))
                self.end_headers()
                self.wfile.write(proc.stdout)
            else:
                self._send_error(404, 'No packets found')
        except subprocess.TimeoutExpired:
            self._send_error(500, 'Stream carving timed out')
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_get_ascii_stream(self, params):
        result, error = self._validate_stream_params(params)
        if error:
            self._send_error(400 if 'required' in error or 'Invalid' in error else 404, error)
            return

        pcap = result['pcap']
        src = result['src']
        sport = result['sport']
        dst = result['dst']
        dport = result['dport']

        try:
            lines = self._extract_payload_lines(pcap, src, sport, dst, dport, 'tcp')
            if not lines:
                lines = self._extract_payload_lines(pcap, src, sport, dst, dport, 'udp')
            full_text = '\n'.join([l['text'] for l in lines])
            truncated = len(full_text) > MAX_TRANSCRIPT_SIZE
            if truncated:
                lines = lines[:config.MAX_TRANSCRIPT_LINES]
            self._send_json({'lines': lines, 'truncated': truncated})
        except subprocess.TimeoutExpired:
            self._send_error(500, 'ASCII transcript extraction timed out')
        except Exception:
            self._send_error(500, 'Internal server error')

    def _extract_payload_lines(self, pcap, src, sport, dst, dport, proto):
        result = subprocess.run(
            ['tshark', '-r', pcap, '-Y',
             f'ip.addr == {src} && ip.addr == {dst} && {proto}.port == {sport} && {proto}.port == {dport}',
             '-T', 'fields', '-e', 'ip.src', '-e', f'{proto}.payload'],
            capture_output=True, text=True, timeout=config.STREAM_TIMEOUT_SECONDS
        )
        lines = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 2:
                continue
            packet_src = parts[0].strip()
            payload_hex = parts[1].replace(':', '') if len(parts) > 1 else ''
            if payload_hex:
                try:
                    payload_bytes = bytes.fromhex(payload_hex)
                    payload_str = payload_bytes.decode('utf-8', errors='replace')
                    cleaned = ''.join(c if c in '\n\r\t' or 32 <= ord(c) < 127 else '.' for c in payload_str)
                    if cleaned.strip():
                        direction = 'src' if packet_src == src else 'dst'
                        lines.append({'text': cleaned, 'direction': direction})
                except (ValueError, UnicodeDecodeError):
                    pass
        return lines

    def handle_get_hexdump_stream(self, params):
        result, error = self._validate_stream_params(params)
        if error:
            self._send_error(400 if 'required' in error or 'Invalid' in error else 404, error)
            return

        pcap = result['pcap']
        src = result['src']
        sport = result['sport']
        dst = result['dst']
        dport = result['dport']

        try:
            proc = subprocess.run(
                ['tcpdump', '-r', pcap, '-X', '-nn',
                 f'host {src} and host {dst} and port {sport} and port {dport}'],
                capture_output=True, text=True, timeout=config.STREAM_TIMEOUT_SECONDS
            )
            packets = []
            current_packet = None
            total_chars = 0
            truncated = False

            for line in proc.stdout.split('\n'):
                if not line.strip():
                    if current_packet:
                        packets.append(current_packet)
                        current_packet = None
                    continue

                if line.startswith('\t0x'):
                    if current_packet:
                        current_packet['lines'].append(line.strip())
                        total_chars += len(line)
                else:
                    if current_packet:
                        packets.append(current_packet)
                    current_packet = {'header': line.strip(), 'lines': []}

                if len(packets) >= config.MAX_HEXDUMP_PACKETS or total_chars > MAX_TRANSCRIPT_SIZE:
                    truncated = True
                    break

            if current_packet:
                packets.append(current_packet)

            self._send_json({'packets': packets, 'truncated': truncated})
        except subprocess.TimeoutExpired:
            self._send_error(500, 'Hexdump extraction timed out')
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_get_analyses(self, params):
        analyses = []
        if os.path.exists(DATA_DIR):
            for md5_dir in os.listdir(DATA_DIR):
                if not MD5_RE.match(md5_dir):
                    continue
                dir_path = os.path.join(DATA_DIR, md5_dir)
                if not os.path.isdir(dir_path):
                    continue
                eve_path = os.path.join(dir_path, 'eve.json')
                db_path = os.path.join(dir_path, 'events.db')
                if os.path.exists(eve_path):
                    eve_size = os.path.getsize(eve_path)
                    if eve_size > MAX_EVE_SIZE:
                        continue
                name_path = os.path.join(dir_path, 'name.txt')
                pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)]

                display_name = md5_dir
                if os.path.exists(name_path) and is_safe_path(dir_path, name_path):
                    with open(name_path, 'r') as f:
                        display_name = f.read().strip()
                elif pcap_files:
                    display_name = pcap_files[0]

                if os.path.exists(eve_path) or os.path.exists(db_path):
                    analyses.append({'md5': md5_dir, 'name': display_name})

            analyses.sort(key=lambda x: x['name'].lower())

        self._send_json(analyses)

    def handle_get_load_analysis(self, params):
        md5 = params.get('md5', [''])[0]
        if not MD5_RE.match(md5):
            self._send_error(400, 'Invalid MD5')
            return

        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_error(400, 'Invalid path')
            return

        eve_path = os.path.join(dir_path, 'eve.json')
        db_path = os.path.join(dir_path, 'events.db')
        name_path = os.path.join(dir_path, 'name.txt')
        pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)] if os.path.exists(dir_path) else []

        if os.path.exists(eve_path) or os.path.exists(db_path):
            if os.path.exists(eve_path):
                eve_size = os.path.getsize(eve_path)
                if eve_size > MAX_EVE_SIZE:
                    self._send_error(400, f'Eve.json too large ({eve_size // (1024*1024)}MB, max {MAX_EVE_SIZE // (1024*1024)}MB)')
                    return

            file_name = md5
            if os.path.exists(name_path) and is_safe_path(dir_path, name_path):
                with open(name_path, 'r') as f:
                    file_name = f.read().strip()
            elif pcap_files:
                file_name = pcap_files[0]

            self._send_json({'success': True, 'md5': md5, 'file_name': file_name})
        else:
            self._send_error(404, 'Analysis not found')

    def handle_get_delete_analysis(self, params):
        md5 = params.get('md5', [''])[0]
        if not MD5_RE.match(md5):
            self._send_error(400, 'Invalid MD5')
            return

        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_error(400, 'Invalid path')
            return

        if os.path.exists(dir_path) and os.path.isdir(dir_path):
            shutil.rmtree(dir_path)
            self._send_json({'success': True})
        else:
            self._send_error(404, 'Analysis not found')

    def handle_get_pcap_path(self, params):
        md5 = params.get('md5', [''])[0]
        if not MD5_RE.match(md5):
            self._send_error(400, 'Invalid MD5')
            return

        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_error(400, 'Invalid path')
            return
        pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)] if os.path.exists(dir_path) else []
        if pcap_files:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            # Return only the filename, not the absolute path
            self.wfile.write(pcap_files[0].encode())
        else:
            self._send_error(404, 'No pcap found')

    def handle_get_version(self, params):
        self._send_json({'version': VERSION})

    def _process_uploaded_file(self, file_data, original_filename, passwords=None):
        """Process uploaded or downloaded file: detect ZIP, extract, find PCAP, compute MD5, dispatch.

        Args:
            file_data: Raw file bytes.
            original_filename: Original filename for password derivation.
            passwords: Optional list of bytes passwords for ZIP extraction.

        Returns:
            dict with 'status' and 'md5' keys.

        Raises:
            ValueError: For extraction or validation failures.
        """
        safe_filename = sanitize_filename(original_filename)
        is_zip = file_data[:2] == b'PK'

        if is_zip:
            tmp_dir = tempfile.mkdtemp()
            try:
                extracted_files = _extract_zip_contents(file_data, tmp_dir, passwords or [])
                pcap_files = [f for f in extracted_files if f.endswith(PCAP_EXTENSIONS)]
                if pcap_files:
                    with open(pcap_files[0], 'rb') as f:
                        pcap_data = f.read()
                    md5_hash = hashlib.md5(pcap_data).hexdigest()
                    dir_path = os.path.join(DATA_DIR, md5_hash)
                    pcap_filename = os.path.basename(pcap_files[0])
                    pcap_path = os.path.join(dir_path, pcap_filename)
                    eve_path = os.path.join(dir_path, 'eve.json')
                    name_path = os.path.join(dir_path, 'name.txt')

                    if os.path.exists(eve_path):
                        return {'status': 'ready', 'md5': md5_hash}

                    os.makedirs(dir_path, exist_ok=True)
                    shutil.move(pcap_files[0], pcap_path)
                    with open(name_path, 'w') as f:
                        f.write(pcap_filename)

                    spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR, 'suricata.yaml'), data_dir=DATA_DIR)
                    return {'status': 'processing', 'md5': md5_hash, 'phase': 'network'}
                else:
                    # ZIP contained no PCAP — treat as standalone file archive
                    non_hidden = [f for f in extracted_files if not os.path.basename(f).startswith('.')]
                    if not non_hidden:
                        raise ValueError('ZIP archive is empty')
                    first_file = non_hidden[0]
                    with open(first_file, 'rb') as f:
                        file_bytes = f.read()
                    md5_hash = hashlib.md5(file_bytes).hexdigest()
                    dir_path = os.path.join(DATA_DIR, md5_hash)
                    dest_path = os.path.join(dir_path, os.path.basename(first_file))
                    db_path = os.path.join(dir_path, 'events.db')
                    name_path = os.path.join(dir_path, 'name.txt')

                    if os.path.exists(db_path):
                        return {'status': 'ready', 'md5': md5_hash}

                    os.makedirs(dir_path, exist_ok=True)
                    shutil.move(first_file, dest_path)
                    self._analyze_standalone_file(dir_path, dest_path, os.path.basename(dest_path))
                    return {'status': 'processing', 'md5': md5_hash, 'phase': 'files'}
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
        else:
            md5_hash = hashlib.md5(file_data).hexdigest()
            dir_path = os.path.join(DATA_DIR, md5_hash)
            dest_filename = safe_filename if safe_filename else 'uploaded'
            dest_path = os.path.join(dir_path, dest_filename)
            eve_path = os.path.join(dir_path, 'eve.json')
            db_path = os.path.join(dir_path, 'events.db')
            name_path = os.path.join(dir_path, 'name.txt')

            if os.path.exists(eve_path) or os.path.exists(db_path):
                return {'status': 'ready', 'md5': md5_hash}

            os.makedirs(dir_path, exist_ok=True)
            with open(dest_path, 'wb') as f:
                f.write(file_data)
            with open(name_path, 'w') as f:
                f.write(dest_filename)

            if is_pcap_file(file_data):
                spawn_suricata(dir_path, dest_path, os.path.join(SURICATA_DIR, 'suricata.yaml'), data_dir=DATA_DIR)
                phase = 'network'
            else:
                self._analyze_standalone_file(dir_path, dest_path, dest_filename)
                phase = 'files'
            return {'status': 'processing', 'md5': md5_hash, 'phase': phase}

    def _analyze_standalone_file(self, dir_path, file_path, safe_filename):
        """Run standalone YARA analysis on a non-PCAP file in the background."""
        def run_analysis():
            phase_file = os.path.join(dir_path, '.phase')
            try:
                with open(phase_file, 'w') as f:
                    f.write('files')
            except OSError:
                pass

            try:
                data_dir = os.environ.get('DATA_DIR', os.path.expanduser('~/ohmypcap-data'))
                rules_file = setup_yara_rules(data_dir)
                db_file = os.path.join(dir_path, 'events.db')
                name_path = os.path.join(dir_path, 'name.txt')

                if rules_file and check_yara_executable():
                    try:
                        matches, sha256, md5, sha1, metadata = scan_single_file(file_path, rules_file)
                        create_file_analysis_db(db_file, file_path, matches, md5, sha1, sha256, metadata=metadata)
                    except Exception as e:
                        _set_error(dir_path, f'YARA scan failed: {e}')
                        create_file_analysis_db(db_file, file_path, [], '', '', '')
                else:
                    create_file_analysis_db(db_file, file_path, [], '', '', '')

                with open(name_path, 'w') as f:
                    f.write(safe_filename)
            except Exception as e:
                _set_error(dir_path, f'Analysis failed: {e}')
            finally:
                try:
                    if os.path.exists(phase_file):
                        os.unlink(phase_file)
                except OSError:
                    pass

        threading.Thread(target=run_analysis, daemon=True).start()

    # ------------------------------------------------------------------
    # POST handlers
    # ------------------------------------------------------------------

    def handle_post_upload(self):
        body = self._read_post_body(MAX_UPLOAD_SIZE)
        if body is None:
            return

        content_length = len(body)
        content_type = self.headers.get('Content-Type', '')
        match = re.search(r'boundary=(.+)', content_type)
        if not match:
            self._send_error(400, 'Invalid request')
            return

        boundary = match.group(1).encode()

        parts = body.split(b'--' + boundary)
        file_data = None
        original_filename = 'unknown.pcap'

        for part in parts:
            if b'filename=' in part:
                header_end = part.find(b'\r\n\r\n')
                if header_end != -1:
                    headers = part[:header_end].decode('utf-8', errors='replace')
                    filename_match = re.search(r'filename="([^"]+)"', headers)
                    if filename_match:
                        original_filename = sanitize_filename(filename_match.group(1))
                        file_data = part[header_end + 4:]
                        if file_data.endswith(b'\r\n'):
                            file_data = file_data[:-2]
                        break

        if not file_data:
            self._send_error(400, 'Invalid file')
            return

        passwords = [b'infected']
        date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', original_filename)
        if date_match:
            year, month, day = date_match.groups()
            passwords.append(f'infected_{year}{month}{day}'.encode())

        try:
            result = self._process_uploaded_file(file_data, original_filename, passwords)
            self._send_json(result)
        except ValueError as exc:
            self._send_error(400, str(exc))
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_post_load_url(self):
        post_data = self._read_post_body(config.MAX_REQUEST_BODY_SIZE)
        if post_data is None:
            return
        data = json.loads(post_data)
        url = data.get('url', '')

        if not url:
            self._send_error(400, 'No URL provided')
            return

        try:
            validate_url_safety(url)

            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=config.URL_DOWNLOAD_TIMEOUT) as response:
                chunk_size = 64 * 1024
                file_data = bytearray()
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    file_data.extend(chunk)
                    if len(file_data) > MAX_UPLOAD_SIZE:
                        self._send_error(413, 'File too large')
                        return
                file_data = bytes(file_data)

            parsed_url = urlparse(url)
            original_filename = os.path.basename(parsed_url.path)
            if not original_filename:
                original_filename = 'downloaded'

            passwords = []
            if 'malware-traffic-analysis.net' in url:
                date_match = re.search(r'/(\d{4})/(\d{2})/(\d{2})/', url)
                if date_match:
                    year, month, day = date_match.groups()
                    passwords.append(f'infected_{year}{month}{day}'.encode())

            result = self._process_uploaded_file(file_data, original_filename, passwords)
            self._send_json(result)
        except ValueError as exc:
            self._send_error(400, str(exc))
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_post_check_status(self):
        post_data = self._read_post_body(config.MAX_REQUEST_BODY_SIZE)
        if post_data is None:
            return
        data = json.loads(post_data)
        md5 = data.get('md5', '')

        if not MD5_RE.match(md5):
            self._send_error(400, 'Invalid MD5')
            return

        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_error(400, 'Invalid path')
            return
        db_file = os.path.join(dir_path, 'events.db')

        # Check for error files first (highest priority)
        error_file = os.path.join(dir_path, '.error')
        if os.path.exists(error_file):
            error_age = time.time() - os.path.getmtime(error_file)
            if error_age > config.STALE_THRESHOLD_SECONDS:
                try:
                    os.unlink(error_file)
                except OSError:
                    pass
            else:
                try:
                    with open(error_file, 'r') as f:
                        error_msg = f.read().strip()
                except OSError:
                    error_msg = 'Analysis failed'
                self._send_json({'status': 'error', 'message': error_msg})
                return

        phase_file = os.path.join(dir_path, '.phase')
        if os.path.exists(phase_file):
            lock_age = time.time() - os.path.getmtime(phase_file)
            if lock_age > config.STALE_THRESHOLD_SECONDS:
                try:
                    os.unlink(phase_file)
                except OSError:
                    pass

        phase = ''
        if os.path.exists(phase_file):
            try:
                with open(phase_file, 'r') as f:
                    phase = f.read().strip()
            except OSError:
                pass

        if os.path.exists(db_file):
            self._send_json({'status': 'ready'})
        else:
            self._send_json({'status': 'processing', 'phase': phase})

    def handle_post_reanalyze(self):
        post_data = self._read_post_body(config.MAX_REQUEST_BODY_SIZE)
        if post_data is None:
            return
        data = json.loads(post_data)
        md5 = data.get('md5', '')

        if not MD5_RE.match(md5):
            self._send_error(400, 'Invalid MD5')
            return

        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_error(400, 'Invalid path')
            return

        if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
            self._send_error(404, 'Analysis not found')
            return

        phase_file = os.path.join(dir_path, '.phase')
        if os.path.exists(phase_file):
            self._send_error(409, 'Analysis already in progress')
            return

        pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)]
        non_pcap_files = [f for f in os.listdir(dir_path)
                          if not f.endswith(PCAP_EXTENSIONS + ('.zip',))
                          and f not in ('eve.json', 'events.db', '.phase', 'yara_matches.json', 'name.txt')]

        # Determine if this is a PCAP or standalone file analysis
        if pcap_files:
            pcap_path = os.path.join(dir_path, pcap_files[0])

            for artifact in ('eve.json', 'events.db', '.phase', '.error', 'yara_matches.json'):
                artifact_path = os.path.join(dir_path, artifact)
                if os.path.exists(artifact_path):
                    try:
                        os.unlink(artifact_path)
                    except OSError:
                        pass

            # Clean up extracted files from previous analysis
            filestore_dir = os.path.join(dir_path, 'filestore')
            if os.path.isdir(filestore_dir):
                try:
                    shutil.rmtree(filestore_dir)
                except OSError:
                    pass

            if spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR, 'suricata.yaml'), data_dir=DATA_DIR):
                self._send_json({'status': 'processing', 'md5': md5, 'phase': 'network'})
            else:
                self._send_error(409, 'Analysis already in progress')
        elif non_pcap_files:
            # Standalone file re-analysis: re-run YARA with updated rules
            file_path = os.path.join(dir_path, non_pcap_files[0])
            for artifact in ('events.db', '.error', 'yara_matches.json'):
                artifact_path = os.path.join(dir_path, artifact)
                if os.path.exists(artifact_path):
                    try:
                        os.unlink(artifact_path)
                    except OSError:
                        pass
            self._analyze_standalone_file(dir_path, file_path, non_pcap_files[0])
            self._send_json({'status': 'processing', 'md5': md5, 'phase': 'files'})
        else:
            self._send_error(404, 'No analysis file found')


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def main():
    """Run OhMyPCAP server."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    os.makedirs(DATA_DIR, exist_ok=True)

    # Check for required executables
    missing = check_executables()
    if missing:
        print(f"Error: Missing required executables: {', '.join(missing)}")
        print("Please install them and try again.")
        sys.exit(1)
    
    # Show banner immediately so users know the app is alive
    title = f'Welcome to OhMyPCAP {VERSION}!'
    padding = ' ' * (61 - len(title))
    print(f"""
    ================================================================
    | {title}{padding}|
    |                                                              |
    | Analyze files from the web or your local collection.         |
    |                                                              |
    | View alerts and then slice and dice your network metadata!   |
    ================================================================
    """)

    # Run setup - handles rules download first
    setup_suricata_config(DATA_DIR)
    setup_yara_rules(DATA_DIR)

    if os.environ.get('DEMO'):
        msg = 'OhMyPCAP is now running. Click the link on the left!'
    else:
        msg = f'OhMyPCAP running at http://{BIND_ADDRESS}:{PORT}/ohmypcap.html'
    padding = ' ' * (61 - len(msg))
    print(f"""
    ================================================================
    | {msg}{padding}|
    ================================================================
    """)
    
    with ThreadedTCPServer((BIND_ADDRESS, PORT), Handler) as httpd:
        httpd.serve_forever()


if __name__ == '__main__':
    main()
