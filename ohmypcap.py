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

from db import get_event_count_sqlite, get_event_types_sqlite, query_events_sqlite
from validators import (
    validate_ip, validate_port, sanitize_filename, is_safe_path,
    validate_url_safety, validate_zip_extraction, validate_pcap_content
)
from suricata import (
    REQUIRED_EXECUTABLES, check_executables, has_internet_access,
    setup_suricata_config, spawn_suricata
)

VERSION = '2.1.0'
PORT = int(os.environ.get('PORT', 8000))
BIND_ADDRESS = os.environ.get('BIND_ADDRESS', '127.0.0.1')
DATA_DIR = os.environ.get('DATA_DIR', os.path.expanduser('~/ohmypcap-data'))
MAX_TRANSCRIPT_SIZE = 100000
MAX_UPLOAD_SIZE = 1000 * 1024 * 1024  # 1000MB
MAX_EVE_SIZE = 1000 * 1024 * 1024  # 1000MB
SURICATA_DIR = os.path.join(DATA_DIR, 'suricata')
SURICATA_RULES_DIR = os.path.join(SURICATA_DIR, 'rules')

PCAP_EXTENSIONS = ('.pcap', '.pcapng', '.cap', '.trace')


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

            if not extracted:
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
        if not re.match(r'^[a-f0-9]{32}$', md5):
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
        else:
            super().do_GET()

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
        if not re.match(r'^[a-f0-9]{32}$', md5):
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
        limit = max(1, min(limit, 5000))
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
        if not re.match(r'^[a-f0-9]{32}$', md5):
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

        if not re.match(r'^[a-f0-9]{32}$', md5):
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
                capture_output=True, timeout=60
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
                lines = lines[:500]
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
            capture_output=True, text=True, timeout=60
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
                except Exception:
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
                capture_output=True, text=True, timeout=60
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

                if len(packets) >= 500 or total_chars > MAX_TRANSCRIPT_SIZE:
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
                if not re.match(r'^[a-f0-9]{32}$', md5_dir):
                    continue
                dir_path = os.path.join(DATA_DIR, md5_dir)
                if not os.path.isdir(dir_path):
                    continue
                eve_path = os.path.join(dir_path, 'eve.json')
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

                if os.path.exists(eve_path):
                    analyses.append({'md5': md5_dir, 'pcap': display_name})

            analyses.sort(key=lambda x: x['pcap'].lower())

        self._send_json(analyses)

    def handle_get_load_analysis(self, params):
        md5 = params.get('md5', [''])[0]
        if not re.match(r'^[a-f0-9]{32}$', md5):
            self._send_error(400, 'Invalid MD5')
            return

        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_error(400, 'Invalid path')
            return

        eve_path = os.path.join(dir_path, 'eve.json')
        name_path = os.path.join(dir_path, 'name.txt')
        pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)] if os.path.exists(dir_path) else []

        if os.path.exists(eve_path):
            eve_size = os.path.getsize(eve_path)
            if eve_size > MAX_EVE_SIZE:
                self._send_error(400, f'Eve.json too large ({eve_size // (1024*1024)}MB, max 1000MB)')
                return

            pcap_name = md5
            if os.path.exists(name_path) and is_safe_path(dir_path, name_path):
                with open(name_path, 'r') as f:
                    pcap_name = f.read().strip()
            elif pcap_files:
                pcap_name = pcap_files[0]

            self._send_json({'success': True, 'md5': md5, 'pcap_name': pcap_name})
        else:
            self._send_error(404, 'Analysis not found')

    def handle_get_delete_analysis(self, params):
        md5 = params.get('md5', [''])[0]
        if not re.match(r'^[a-f0-9]{32}$', md5):
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
        if not re.match(r'^[a-f0-9]{32}$', md5):
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
            self.wfile.write(os.path.join(dir_path, pcap_files[0]).encode())
        else:
            self._send_error(404, 'No pcap found')

    def handle_get_version(self, params):
        self._send_json({'version': VERSION})

    # ------------------------------------------------------------------
    # POST handlers
    # ------------------------------------------------------------------

    def handle_post_upload(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_UPLOAD_SIZE:
            self._send_error(413, 'File too large')
            return

        content_type = self.headers.get('Content-Type', '')
        match = re.search(r'boundary=(.+)', content_type)
        if not match:
            self._send_error(400, 'Invalid request')
            return

        boundary = match.group(1).encode()
        body = self.rfile.read(content_length)

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
                        if original_filename.endswith(PCAP_EXTENSIONS + ('.zip',)):
                            file_data = part[header_end + 4:]
                            if file_data.endswith(b'\r\n'):
                                file_data = file_data[:-2]
                            break

        if not file_data:
            self._send_error(400, 'Invalid file')
            return

        if not validate_pcap_content(file_data):
            self._send_error(400, 'Invalid file content')
            return

        safe_filename = sanitize_filename(original_filename)

        try:
            if safe_filename.endswith('.zip'):
                tmp_dir = tempfile.mkdtemp()
                try:
                    passwords = [b'infected']
                    date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', safe_filename)
                    if date_match:
                        year, month, day = date_match.groups()
                        passwords.append(f'infected_{year}{month}{day}'.encode())

                    pcap_data, pcap_filename = extract_pcap_from_zip(file_data, tmp_dir, passwords)
                    md5_hash = hashlib.md5(pcap_data).hexdigest()

                    dir_path = os.path.join(DATA_DIR, md5_hash)
                    eve_path = os.path.join(dir_path, 'eve.json')
                    name_path = os.path.join(dir_path, 'name.txt')
                    pcap_path = os.path.join(dir_path, pcap_filename)

                    is_new = not os.path.exists(eve_path)

                    if is_new:
                        if not is_safe_path(dir_path, pcap_path):
                            self._send_error(400, 'Invalid filename')
                            return
                        os.makedirs(dir_path, exist_ok=True)
                        extracted_pcap = os.path.join(tmp_dir, pcap_filename)
                        shutil.move(extracted_pcap, pcap_path)
                        with open(name_path, 'w') as f:
                            f.write(pcap_filename)

                        spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR, 'suricata.yaml'))
                        self._send_json({'status': 'processing', 'md5': md5_hash})
                    else:
                        self._send_json({'status': 'ready', 'md5': md5_hash})
                except ValueError as exc:
                    self._send_error(400, str(exc))
                    return
                finally:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
            else:
                md5_hash = hashlib.md5(file_data).hexdigest()
                dir_path = os.path.join(DATA_DIR, md5_hash)
                pcap_path = os.path.join(dir_path, safe_filename)

                if not is_safe_path(dir_path, pcap_path):
                    self._send_error(400, 'Invalid filename')
                    return

                eve_path = os.path.join(dir_path, 'eve.json')
                name_path = os.path.join(dir_path, 'name.txt')

                is_new = not os.path.exists(eve_path)

                if is_new:
                    os.makedirs(dir_path, exist_ok=True)
                    with open(pcap_path, 'wb') as f:
                        f.write(file_data)
                    with open(name_path, 'w') as f:
                        f.write(safe_filename)

                    spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR, 'suricata.yaml'))
                    self._send_json({'status': 'processing', 'md5': md5_hash})
                else:
                    self._send_json({'status': 'ready', 'md5': md5_hash})
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_post_load_url(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 1024 * 1024:
            self._send_error(413, 'Request too large')
            return

        post_data = self.rfile.read(content_length)
        data = json.loads(post_data)
        url = data.get('url', '')

        if not url:
            self._send_error(400, 'No URL provided')
            return

        try:
            validate_url_safety(url)

            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            validate_url_safety(url)
            with urllib.request.urlopen(req, timeout=30) as response:
                file_data = response.read()

            if len(file_data) > MAX_UPLOAD_SIZE:
                self._send_error(413, 'File too large')
                return

            if not validate_pcap_content(file_data):
                self._send_error(400, 'Invalid file content')
                return

            parsed_url = urlparse(url)
            original_filename = sanitize_filename(os.path.basename(parsed_url.path))
            if not original_filename:
                original_filename = 'downloaded.pcap'

            if original_filename.endswith('.zip'):
                tmp_extract_dir = tempfile.mkdtemp()
                try:
                    passwords = []
                    if 'malware-traffic-analysis.net' in url:
                        date_match = re.search(r'/(\d{4})/(\d{2})/(\d{2})/', url)
                        if date_match:
                            year, month, day = date_match.groups()
                            passwords.append(f'infected_{year}{month}{day}'.encode())

                    pcap_data, pcap_filename = extract_pcap_from_zip(file_data, tmp_extract_dir, passwords)
                    md5_hash = hashlib.md5(pcap_data).hexdigest()

                    dir_path = os.path.join(DATA_DIR, md5_hash)
                    eve_path = os.path.join(dir_path, 'eve.json')
                    name_path = os.path.join(dir_path, 'name.txt')
                    pcap_path = os.path.join(dir_path, pcap_filename)

                    if os.path.exists(eve_path):
                        self._send_json({'status': 'ready', 'md5': md5_hash})
                        return

                    if not is_safe_path(dir_path, pcap_path):
                        raise Exception('Invalid filename')
                    os.makedirs(dir_path, exist_ok=True)
                    extracted_pcap = os.path.join(tmp_extract_dir, pcap_filename)
                    shutil.move(extracted_pcap, pcap_path)
                    with open(name_path, 'w') as f:
                        f.write(sanitize_filename(pcap_filename))
                finally:
                    shutil.rmtree(tmp_extract_dir, ignore_errors=True)
            else:
                md5_hash = hashlib.md5(file_data).hexdigest()
                dir_path = os.path.join(DATA_DIR, md5_hash)
                eve_path = os.path.join(dir_path, 'eve.json')
                name_path = os.path.join(dir_path, 'name.txt')

                if os.path.exists(eve_path):
                    self._send_json({'status': 'ready', 'md5': md5_hash})
                    return

                os.makedirs(dir_path, exist_ok=True)
                safe_filename = sanitize_filename(original_filename)
                pcap_path = os.path.join(dir_path, safe_filename)
                if not is_safe_path(dir_path, pcap_path):
                    raise Exception('Invalid filename')
                with open(pcap_path, 'wb') as f:
                    f.write(file_data)
                with open(name_path, 'w') as f:
                    f.write(sanitize_filename(original_filename))

                pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)]
                if not pcap_files:
                    raise Exception('No pcap file found')
                pcap_path = os.path.join(dir_path, pcap_files[0])

            spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR, 'suricata.yaml'))
            self._send_json({'status': 'processing', 'md5': md5_hash})

        except ValueError:
            self._send_error(400, 'Invalid URL')
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_post_check_status(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data)
        md5 = data.get('md5', '')

        if not re.match(r'^[a-f0-9]{32}$', md5):
            self._send_error(400, 'Invalid MD5')
            return

        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_error(400, 'Invalid path')
            return
        db_file = os.path.join(dir_path, 'events.db')

        processing_lock = os.path.join(dir_path, '.processing')
        if os.path.exists(processing_lock):
            lock_age = time.time() - os.path.getmtime(processing_lock)
            if lock_age > 600:
                try:
                    os.unlink(processing_lock)
                except Exception:
                    pass

        if os.path.exists(db_file):
            self._send_json({'status': 'ready'})
        else:
            self._send_json({'status': 'processing'})

    def handle_post_reanalyze(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data)
        md5 = data.get('md5', '')

        if not re.match(r'^[a-f0-9]{32}$', md5):
            self._send_error(400, 'Invalid MD5')
            return

        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            self._send_error(400, 'Invalid path')
            return

        if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
            self._send_error(404, 'Analysis not found')
            return

        pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)]
        if not pcap_files:
            self._send_error(404, 'No pcap found')
            return

        pcap_path = os.path.join(dir_path, pcap_files[0])

        for artifact in ('eve.json', 'events.db', '.processing'):
            artifact_path = os.path.join(dir_path, artifact)
            if os.path.exists(artifact_path):
                try:
                    os.unlink(artifact_path)
                except Exception:
                    pass

        if spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR, 'suricata.yaml')):
            self._send_json({'status': 'processing', 'md5': md5})
        else:
            self._send_error(409, 'Analysis already in progress')


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(script_dir, 'ohmypcap.html')
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
    | Analyze pcap files from the web or your local collection.    |
    |                                                              |
    | View alerts and then slice and dice your network metadata!   |
    ================================================================
    """)

    # Run setup - handles rules download first
    setup_suricata_config(DATA_DIR)

    msg = f'OhMyPCAP running at http://{BIND_ADDRESS}:{PORT}/ohmypcap.html'
    padding = ' ' * (61 - len(msg))
    print(f"""
    ================================================================
    | {msg}{padding}|
    ================================================================
    """)
    
    with ThreadedTCPServer((BIND_ADDRESS, PORT), Handler) as httpd:
        httpd.serve_forever()
