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
import ipaddress
import time
import socket
import sqlite3
import shutil
import sys
import threading

VERSION = '2.0.0'
PORT = int(os.environ.get('PORT', 8000))
BIND_ADDRESS = os.environ.get('BIND_ADDRESS', '127.0.0.1')
DATA_DIR = os.environ.get('DATA_DIR', os.path.expanduser('~/ohmypcap-data'))
MAX_TRANSCRIPT_SIZE = 100000
MAX_UPLOAD_SIZE = 1000 * 1024 * 1024  # 1000MB
MAX_EVE_SIZE = 1000 * 1024 * 1024  # 1000MB
SURICATA_DIR = os.path.join(DATA_DIR, 'suricata')
SURICATA_RULES_DIR = os.path.join(SURICATA_DIR, 'rules')
ALLOWED_URL_SCHEMES = ('http', 'https')
BLOCKED_HOSTS = ('localhost', '127.0.0.1', '0.0.0.0', '::1')
BLOCKED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fd00::/8'),
]

REQUIRED_EXECUTABLES = ['tcpdump', 'tshark', 'suricata', 'suricata-update']

def check_executables():
    """Check all required executables exist. Returns list of missing tools."""
    missing = []
    for tool in REQUIRED_EXECUTABLES:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing

os.makedirs(DATA_DIR, exist_ok=True)

PCAP_EXTENSIONS = ('.pcap', '.pcapng', '.cap', '.trace')

def has_internet_access():
    try:
        socket.create_connection(("rules.emergingthreats.net", 80), timeout=5)
        return True
    except OSError:
        return False

def setup_suricata_config():
    os.makedirs(SURICATA_DIR, exist_ok=True)
    os.makedirs(SURICATA_RULES_DIR, exist_ok=True)
    
    if os.path.isdir('/etc/suricata'):
        needs_copy = False
        if not os.path.exists(os.path.join(SURICATA_DIR, 'suricata.yaml')):
            needs_copy = True
        
        if needs_copy:
            for item in os.listdir('/etc/suricata'):
                src = os.path.join('/etc/suricata', item)
                dst = os.path.join(SURICATA_DIR, item)
                if os.path.isfile(src):
                    try:
                        shutil.copy2(src, dst)
                    except Exception as e:
                        print(f'Warning: could not copy {src} to {dst}: {e}')
                elif os.path.isdir(src):
                    try:
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    except Exception as e:
                        print(f'Warning: could not copy directory {src} to {dst}: {e}')
    
    # Update rule path in suricata.yaml to use our directory
    suricata_config = os.path.join(SURICATA_DIR, 'suricata.yaml')
    if os.path.exists(suricata_config):
        with open(suricata_config, 'r') as f:
            config_content = f.read()
        config_content = config_content.replace('/var/lib/suricata/rules', SURICATA_RULES_DIR)
        # Enable SCADA/ICS protocol parsers
        for proto in ('pgsql', 'modbus', 'dnp3', 'enip'):
            config_content = re.sub(
                rf'(\s+{proto}:\s*\n\s+)enabled:\s*no',
                r'\1enabled: yes',
                config_content
            )
        with open(suricata_config, 'w') as f:
            f.write(config_content)
    
    disable_conf = os.path.join(SURICATA_DIR, 'disable.conf')
    if not os.path.exists(disable_conf):
        with open(disable_conf, 'w') as f:
            f.write('re:classtype:protocol-command-decode\n')
    
    # Determine whether to update rules or use baked-in rules
    rules_exist = os.path.exists(os.path.join(SURICATA_RULES_DIR, 'suricata.rules'))
    baked_in_rules_dir = '/usr/share/suricata/rules'
    baked_in_rules_exist = os.path.isdir(baked_in_rules_dir) and os.path.exists(os.path.join(baked_in_rules_dir, 'suricata.rules'))

    print("Checking for internet access...")
    if has_internet_access():
        print("Internet access detected — updating Suricata rules...")
        try:
            subprocess.run(
                ['suricata-update', '--no-test', '-c', suricata_config, '--data-dir', SURICATA_DIR, '--disable-conf', disable_conf, '--output', SURICATA_RULES_DIR],
                timeout=60
            )
            print("Suricata rules updated successfully")
        except Exception as e:
            print(f'suricata-update warning: {e}')
    elif baked_in_rules_exist:
        print("No internet access detected — using baked-in Suricata rules")
        try:
            shutil.copytree(baked_in_rules_dir, SURICATA_RULES_DIR, dirs_exist_ok=True)
            print("Baked-in rules copied successfully")
        except Exception as e:
            print(f'Warning: could not copy baked-in rules: {e}')
    else:
        print("Warning: no baked-in rules found and no internet access — Suricata may not have rules to use")

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return True

def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_port(port_str):
    try:
        port = int(port_str)
        return 0 <= port <= 65535
    except (ValueError, TypeError):
        return False

def sanitize_filename(filename):
    return os.path.basename(filename.replace('\\', '/'))

def is_safe_path(base, path):
    real_base = os.path.realpath(base)
    real_path = os.path.realpath(path)
    return real_path.startswith(real_base + os.sep) or real_path == real_base

def validate_url_safety(url):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        raise ValueError(f"Only HTTP/HTTPS URLs are allowed")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: no hostname")

    if hostname.lower() in [h.lower() for h in BLOCKED_HOSTS]:
        raise ValueError("Access to localhost is not allowed")

    try:
        addrinfo = socket.getaddrinfo(hostname, None)
        resolved_ips = set()
        for info in addrinfo:
            resolved_ips.add(info[4][0])
        for addr in resolved_ips:
            ip = ipaddress.ip_address(addr)
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    raise ValueError(f"Access to private/internal addresses is not allowed ({addr})")
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")

def validate_zip_extraction(zip_ref, extract_path):
    for member in zip_ref.namelist():
        member_path = os.path.realpath(os.path.join(extract_path, member))
        if not member_path.startswith(os.path.realpath(extract_path) + os.sep):
            raise ValueError(f"Zip slip detected: {member}")

def validate_pcap_content(data):
    if len(data) < 4:
        return False
    magic = data[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return True
    if magic == b'\x0a\x0d\x0d\x0a':
        return True
    if magic in (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'):
        return True
    return False

SQLITE_SCHEMA = '''
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    timestamp TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    app_proto TEXT,
    json_data TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp);
'''

def create_sqlite_db(db_path, eve_file):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.executescript(SQLITE_SCHEMA)
    
    try:
        with open(eve_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    event_type = event.get('event_type', '')
                    timestamp = event.get('timestamp', '')
                    
                    src_ip = event.get('src_ip', event.get('source', {}).get('ip', ''))
                    src_port = event.get('src_port', event.get('source', {}).get('port', 0))
                    dest_ip = event.get('dest_ip', event.get('destination', {}).get('ip', ''))
                    dest_port = event.get('dest_port', event.get('destination', {}).get('port', 0))
                    protocol = event.get('proto', '')
                    app_proto = event.get('app_proto', '')
                    
                    conn.execute(
                        '''INSERT INTO events (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, json_data)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, line)
                    )
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass
    
    conn.commit()
    conn.close()

def query_events_sqlite(db_path, event_type=None, offset=0, limit=1000):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    
    if event_type:
        cursor = conn.execute(
            '''SELECT json_data FROM events WHERE event_type = ? ORDER BY timestamp LIMIT ? OFFSET ?''',
            (event_type, limit, offset)
        )
    else:
        cursor = conn.execute(
            '''SELECT json_data FROM events ORDER BY timestamp LIMIT ? OFFSET ?''',
            (limit, offset)
        )
    
    results = [json.loads(row['json_data']) for row in cursor.fetchall()]
    conn.close()
    return results

def get_event_count_sqlite(db_path, event_type=None):
    conn = sqlite3.connect(db_path, timeout=30)
    if event_type:
        cursor = conn.execute('SELECT COUNT(*) FROM events WHERE event_type = ?', (event_type,))
    else:
        cursor = conn.execute('SELECT COUNT(*) FROM events')
    count = cursor.fetchone()[0]
    conn.close()
    return count

def get_event_types_sqlite(db_path):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute('SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC')
    results = {row['event_type']: row['cnt'] for row in cursor.fetchall()}
    conn.close()
    return results

def spawn_suricata(dir_path, pcap_path):
    """Spawn Suricata in the background to analyze a PCAP.

    Returns True if a new Suricata process was started.
    Returns False if analysis is already in progress (lock exists).
    """
    processing_lock = os.path.join(dir_path, '.processing')
    if os.path.exists(processing_lock):
        return False

    open(processing_lock, 'w').close()

    def on_suricata_done():
        try:
            os.unlink(processing_lock)
        except Exception:
            pass
        eve_file = os.path.join(dir_path, 'eve.json')
        db_file = os.path.join(dir_path, 'events.db')
        if os.path.exists(eve_file) and not os.path.exists(db_file):
            try:
                create_sqlite_db(db_file, eve_file)
            except Exception:
                pass

    try:
        proc = subprocess.Popen(
            ['suricata', '-r', pcap_path, '-c', os.path.join(SURICATA_DIR, 'suricata.yaml'),
             '-k', 'none', '--runmode', 'single',
             '--set', 'outputs.1.eve-log.types.0.alert.metadata.rule.raw=true'],
            cwd=dir_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        threading.Thread(target=lambda: (proc.wait(), on_suricata_done()), daemon=True).start()
        return True
    except Exception:
        try:
            os.unlink(processing_lock)
        except Exception:
            pass
        return False

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

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == '/':
            # Redirect root path to ohmypcap.html
            self.send_response(301)
            self.send_header('Location', '/ohmypcap.html')
            self.end_headers()
            return

        if path == '/favicon.ico':
            self.send_response(204)
            self.end_headers()
            return

        if path == '/api/events':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            md5 = params.get('md5', [''])[0]
            if not md5:
                self.wfile.write(b'[]')
                return
            if not re.match(r'^[a-f0-9]{32}$', md5):
                self.wfile.write(b'[]')
                return
            dir_path = os.path.join(DATA_DIR, md5)
            if not is_safe_path(DATA_DIR, dir_path):
                self.wfile.write(b'[]')
                return
            
            try:
                offset = int(params.get('offset', ['0'])[0])
                limit = int(params.get('limit', ['1000'])[0])
            except ValueError:
                self.wfile.write(b'[]')
                return

            offset = max(0, offset)
            limit = max(1, min(limit, 5000))
            event_type = params.get('type', [''])[0] or None
            
            db_file = os.path.join(dir_path, 'events.db')

            if db_file and os.path.exists(db_file):
                events = query_events_sqlite(db_file, event_type, offset, limit)
                self.wfile.write(json.dumps(events).encode())
            else:
                self.wfile.write(b'[]')

        elif path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            md5 = params.get('md5', [''])[0]
            if not md5:
                self.wfile.write(json.dumps({'error': 'md5 parameter required'}).encode())
                return
            if not re.match(r'^[a-f0-9]{32}$', md5):
                self.wfile.write(json.dumps({}).encode())
                return
            dir_path = os.path.join(DATA_DIR, md5)
            if not is_safe_path(DATA_DIR, dir_path):
                self.wfile.write(json.dumps({}).encode())
                return
            db_file = os.path.join(dir_path, 'events.db')

            stats = {}
            if os.path.exists(db_file):
                stats = get_event_types_sqlite(db_file)
            self.wfile.write(json.dumps(stats).encode())

        elif path == '/api/count':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            md5 = params.get('md5', [''])[0]
            if not md5:
                self.wfile.write(json.dumps({'error': 'md5 parameter required'}).encode())
                return
            event_type = params.get('type', [''])[0] or None
            
            if not re.match(r'^[a-f0-9]{32}$', md5):
                self.wfile.write(json.dumps({'count': 0}).encode())
                return
            dir_path = os.path.join(DATA_DIR, md5)
            if not is_safe_path(DATA_DIR, dir_path):
                self.wfile.write(json.dumps({'count': 0}).encode())
                return
            db_file = os.path.join(dir_path, 'events.db')

            if os.path.exists(db_file):
                count = get_event_count_sqlite(db_file, event_type)
            else:
                count = 0
            self.wfile.write(json.dumps({'count': count}).encode())

        elif path == '/api/download-stream':
            src = params.get('src', [''])[0]
            sport = params.get('sport', [''])[0]
            dst = params.get('dst', [''])[0]
            dport = params.get('dport', [''])[0]
            md5 = params.get('md5', [''])[0]

            if not md5:
                self._send_error(400, 'md5 parameter required')
                return

            if not (validate_ip(src) and validate_ip(dst) and validate_port(sport) and validate_port(dport)):
                self._send_error(400, 'Invalid IP or port')
                return

            if not re.match(r'^[a-f0-9]{32}$', md5):
                self._send_error(400, 'Invalid MD5')
                return
            dir_path = os.path.join(DATA_DIR, md5)
            if not is_safe_path(DATA_DIR, dir_path):
                self._send_error(400, 'Invalid path')
                return
            pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)] if os.path.exists(dir_path) else []
            pcap = os.path.join(dir_path, pcap_files[0]) if pcap_files else None

            if not pcap:
                self._send_error(404, 'No pcap file found')
                return

            try:
                result = subprocess.run(
                    ['tcpdump', '-r', pcap, '-w', '-', f"host {src} and host {dst} and port {sport} and port {dport}"],
                    capture_output=True, timeout=60
                )
                if result.returncode == 0 and len(result.stdout) > 0:
                    filename = f"stream_{src}_{sport}_to_{dst}_{dport}.pcap"
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
                    self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                    self.send_header('Content-Length', str(len(result.stdout)))
                    self.end_headers()
                    self.wfile.write(result.stdout)
                else:
                    self._send_error(404, 'No packets found')
            except subprocess.TimeoutExpired:
                self._send_error(500, 'Stream carving timed out')
            except Exception:
                self._send_error(500, 'Internal server error')

        elif path == '/api/ascii-stream':
            src = params.get('src', [''])[0]
            sport = params.get('sport', [''])[0]
            dst = params.get('dst', [''])[0]
            dport = params.get('dport', [''])[0]
            md5 = params.get('md5', [''])[0]

            if not md5:
                self._send_error(400, 'md5 parameter required')
                return

            if not (validate_ip(src) and validate_ip(dst) and validate_port(sport) and validate_port(dport)):
                self._send_error(400, 'Invalid IP or port')
                return

            if not re.match(r'^[a-f0-9]{32}$', md5):
                self._send_error(400, 'Invalid MD5')
                return
            dir_path = os.path.join(DATA_DIR, md5)
            if not is_safe_path(DATA_DIR, dir_path):
                self._send_error(400, 'Invalid path')
                return
            pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)] if os.path.exists(dir_path) else []
            pcap = os.path.join(dir_path, pcap_files[0]) if pcap_files else None

            if not pcap:
                self._send_error(404, 'No pcap file found')
                return

            try:
                # Get TCP payload with source IP to determine direction
                result = subprocess.run(
                    ['tshark', '-r', pcap, '-Y', f'ip.addr == {src} && ip.addr == {dst} && tcp.port == {sport} && tcp.port == {dport}', '-T', 'fields', '-e', 'ip.src', '-e', 'tcp.payload'],
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
                if not lines:
                    # Try UDP
                    result = subprocess.run(
                        ['tshark', '-r', pcap, '-Y', f'ip.addr == {src} && ip.addr == {dst} && udp.port == {sport} && udp.port == {dport}', '-T', 'fields', '-e', 'ip.src', '-e', 'udp.payload'],
                        capture_output=True, text=True, timeout=60
                    )
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
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                full_text = '\n'.join([l['text'] for l in lines])
                truncated = len(full_text) > MAX_TRANSCRIPT_SIZE
                if truncated:
                    lines = lines[:500]  # Approximate limit
                self.wfile.write(json.dumps({'lines': lines, 'truncated': truncated}).encode())
            except subprocess.TimeoutExpired:
                self._send_error(500, 'ASCII transcript extraction timed out')
            except Exception:
                self._send_error(500, 'Internal server error')

        elif path == '/api/hexdump-stream':
            src = params.get('src', [''])[0]
            sport = params.get('sport', [''])[0]
            dst = params.get('dst', [''])[0]
            dport = params.get('dport', [''])[0]
            md5 = params.get('md5', [''])[0]

            if not md5:
                self._send_error(400, 'md5 parameter required')
                return

            if not (validate_ip(src) and validate_ip(dst) and validate_port(sport) and validate_port(dport)):
                self._send_error(400, 'Invalid IP or port')
                return

            if not re.match(r'^[a-f0-9]{32}$', md5):
                self._send_error(400, 'Invalid MD5')
                return
            dir_path = os.path.join(DATA_DIR, md5)
            if not is_safe_path(DATA_DIR, dir_path):
                self._send_error(400, 'Invalid path')
                return
            pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)] if os.path.exists(dir_path) else []
            pcap = os.path.join(dir_path, pcap_files[0]) if pcap_files else None

            if not pcap:
                self._send_error(404, 'No pcap file found')
                return

            try:
                result = subprocess.run(
                    ['tcpdump', '-r', pcap, '-X', '-nn',
                     f'host {src} and host {dst} and port {sport} and port {dport}'],
                    capture_output=True, text=True, timeout=60
                )
                packets = []
                current_packet = None
                total_chars = 0
                truncated = False

                for line in result.stdout.split('\n'):
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

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'packets': packets, 'truncated': truncated}).encode())
            except subprocess.TimeoutExpired:
                self._send_error(500, 'Hexdump extraction timed out')
            except Exception:
                self._send_error(500, 'Internal server error')

        elif path == '/api/analyses':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
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

            self.wfile.write(json.dumps(analyses).encode())

        elif path == '/api/load-analysis':
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

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'md5': md5, 'pcap_name': pcap_name}).encode())
            else:
                self._send_error(404, 'Analysis not found')

        elif path == '/api/delete-analysis':
            md5 = params.get('md5', [''])[0]
            if not re.match(r'^[a-f0-9]{32}$', md5):
                self._send_error(400, 'Invalid MD5')
                return

            dir_path = os.path.join(DATA_DIR, md5)
            if not is_safe_path(DATA_DIR, dir_path):
                self._send_error(400, 'Invalid path')
                return

            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                import shutil
                shutil.rmtree(dir_path)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True}).encode())
            else:
                self._send_error(404, 'Analysis not found')

        elif path == '/api/pcap-path':
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

        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/api/upload':
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
                    # Extract ZIP to temp, hash the PCAP inside
                    tmp_dir = tempfile.mkdtemp()
                    tmp_zip = os.path.join(tmp_dir, safe_filename)
                    try:
                        with open(tmp_zip, 'wb') as f:
                            f.write(file_data)

                        with zipfile.ZipFile(tmp_zip, 'r') as zip_ref:
                            validate_zip_extraction(zip_ref, tmp_dir)
                            extracted = False
                            # Try no password first
                            try:
                                zip_ref.extractall(tmp_dir)
                                extracted = True
                            except RuntimeError:
                                pass

                            # Try common passwords for malware-traffic-analysis.net zips
                            if not extracted:
                                passwords = [b'infected']
                                # Try deriving date-based password from filename (e.g., 2026-02-03-...)
                                date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', safe_filename)
                                if date_match:
                                    year, month, day = date_match.groups()
                                    passwords.append(f'infected_{year}{month}{day}'.encode())

                                for pwd in passwords:
                                    try:
                                        zip_ref.extractall(tmp_dir, pwd=pwd)
                                        extracted = True
                                        break
                                    except RuntimeError:
                                        continue

                            if not extracted:
                                self._send_error(400, 'Password-protected ZIP could not be opened. Please extract the PCAP first.')
                                return

                        pcap_files = [f for f in os.listdir(tmp_dir) if f.endswith(PCAP_EXTENSIONS)]
                        if not pcap_files:
                            self._send_error(400, 'No pcap file found in zip archive')
                            return

                        extracted_pcap = os.path.join(tmp_dir, pcap_files[0])
                        with open(extracted_pcap, 'rb') as f:
                            pcap_data = f.read()
                        md5_hash = hashlib.md5(pcap_data).hexdigest()

                        dir_path = os.path.join(DATA_DIR, md5_hash)
                        eve_path = os.path.join(dir_path, 'eve.json')
                        name_path = os.path.join(dir_path, 'name.txt')
                        pcap_path = os.path.join(dir_path, pcap_files[0])

                        is_new = not os.path.exists(eve_path)

                        if is_new:
                            if not is_safe_path(dir_path, pcap_path):
                                self._send_error(400, 'Invalid filename')
                                return
                            os.makedirs(dir_path, exist_ok=True)
                            shutil.move(extracted_pcap, pcap_path)
                            with open(name_path, 'w') as f:
                                f.write(pcap_files[0])

                            spawn_suricata(dir_path, pcap_path)
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({'status': 'processing', 'md5': md5_hash}).encode())
                        else:
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({'status': 'ready', 'md5': md5_hash}).encode())
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

                        spawn_suricata(dir_path, pcap_path)
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'status': 'processing', 'md5': md5_hash}).encode())
                    else:
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'status': 'ready', 'md5': md5_hash}).encode())
            except Exception:
                self._send_error(500, 'Internal server error')

        elif self.path == '/api/load-url':
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
                # Re-validate immediately before opening to narrow DNS rebinding window
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
                    password = None
                    if 'malware-traffic-analysis.net' in url:
                        date_match = re.search(r'/(\d{4})/(\d{2})/(\d{2})/', url)
                        if date_match:
                            year, month, day = date_match.groups()
                            password = f'infected_{year}{month}{day}'.encode()

                    tmp_extract_dir = tempfile.mkdtemp()
                    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_zip:
                        tmp_zip.write(file_data)
                        tmp_zip_path = tmp_zip.name

                    try:
                        with zipfile.ZipFile(tmp_zip_path, 'r') as zip_ref:
                            validate_zip_extraction(zip_ref, tmp_extract_dir)
                            try:
                                zip_ref.extractall(tmp_extract_dir)
                            except RuntimeError:
                                if password:
                                    zip_ref.extractall(tmp_extract_dir, pwd=password)
                                else:
                                    raise

                        pcap_files = [f for f in os.listdir(tmp_extract_dir) if f.endswith(PCAP_EXTENSIONS)]
                        if not pcap_files:
                            raise Exception('No pcap file found in zip archive')

                        extracted_pcap = os.path.join(tmp_extract_dir, pcap_files[0])
                        with open(extracted_pcap, 'rb') as f:
                            pcap_data = f.read()
                        md5_hash = hashlib.md5(pcap_data).hexdigest()

                        dir_path = os.path.join(DATA_DIR, md5_hash)
                        eve_path = os.path.join(dir_path, 'eve.json')
                        name_path = os.path.join(dir_path, 'name.txt')
                        pcap_path = os.path.join(dir_path, pcap_files[0])

                        if os.path.exists(eve_path):
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({'status': 'ready', 'md5': md5_hash}).encode())
                            return

                        if not is_safe_path(dir_path, pcap_path):
                            raise Exception('Invalid filename')
                        os.makedirs(dir_path, exist_ok=True)
                        shutil.move(extracted_pcap, pcap_path)
                        with open(name_path, 'w') as f:
                            f.write(sanitize_filename(pcap_files[0]))
                    finally:
                        os.unlink(tmp_zip_path)
                        shutil.rmtree(tmp_extract_dir, ignore_errors=True)
                else:
                    md5_hash = hashlib.md5(file_data).hexdigest()
                    dir_path = os.path.join(DATA_DIR, md5_hash)
                    eve_path = os.path.join(dir_path, 'eve.json')
                    name_path = os.path.join(dir_path, 'name.txt')

                    if os.path.exists(eve_path):
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'status': 'ready', 'md5': md5_hash}).encode())
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

                spawn_suricata(dir_path, pcap_path)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'processing', 'md5': md5_hash}).encode())

            except ValueError:
                self._send_error(400, 'Invalid URL')
            except Exception:
                self._send_error(500, 'Internal server error')

        elif self.path == '/api/check-status':
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
            eve_path = os.path.join(dir_path, 'eve.json')
            db_file = os.path.join(dir_path, 'events.db')
            pcap_files = [f for f in os.listdir(dir_path) if f.endswith(PCAP_EXTENSIONS)] if os.path.exists(dir_path) else []
            pcap_path = os.path.join(dir_path, pcap_files[0]) if pcap_files else None

            processing_lock = os.path.join(dir_path, '.processing')
            # Treat stale locks (> 10 minutes) as expired to recover from crashed Suricata runs
            if os.path.exists(processing_lock):
                lock_age = time.time() - os.path.getmtime(processing_lock)
                if lock_age > 600:
                    try:
                        os.unlink(processing_lock)
                    except Exception:
                        pass

            is_ready = False
            if os.path.exists(db_file):
                is_ready = True

            if is_ready:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'ready'}).encode())
            else:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'processing'}).encode())

        elif self.path == '/api/reanalyze':
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

            # Delete old analysis artifacts, keep PCAP and name.txt
            for artifact in ('eve.json', 'events.db', '.processing'):
                artifact_path = os.path.join(dir_path, artifact)
                if os.path.exists(artifact_path):
                    try:
                        os.unlink(artifact_path)
                    except Exception:
                        pass

            if spawn_suricata(dir_path, pcap_path):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'processing', 'md5': md5}).encode())
            else:
                self._send_error(409, 'Analysis already in progress')

        else:
            self._send_error(404, 'Not found')

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(script_dir, 'ohmypcap.html')
    os.chdir(script_dir)
    
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
    setup_suricata_config()

    msg = f'OhMyPCAP running at http://{BIND_ADDRESS}:{PORT}/ohmypcap.html'
    padding = ' ' * (61 - len(msg))
    print(f"""
    ================================================================
    | {msg}{padding}|
    ================================================================
    """)
    
    with ThreadedTCPServer((BIND_ADDRESS, PORT), Handler) as httpd:
        httpd.serve_forever()
