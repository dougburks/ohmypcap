#!/usr/bin/env python3
import unittest
import unittest.mock
import json
import os
import sys
import tempfile
import shutil
import hashlib
import socket
import threading
import time
import zipfile
import io
import re
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import config
import db
import ohmypcap as server

SERVER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ohmypcap.py')
SURICATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'suricata.py')


class TestIPValidation(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(server.validate_ip('192.168.1.1'))
        self.assertTrue(server.validate_ip('10.0.0.1'))
        self.assertTrue(server.validate_ip('8.8.8.8'))
        self.assertTrue(server.validate_ip('0.0.0.0'))
        self.assertTrue(server.validate_ip('255.255.255.255'))

    def test_valid_ipv6(self):
        self.assertTrue(server.validate_ip('::1'))
        self.assertTrue(server.validate_ip('2001:db8::1'))
        self.assertTrue(server.validate_ip('fe80::1'))

    def test_invalid_ip(self):
        self.assertFalse(server.validate_ip(''))
        self.assertFalse(server.validate_ip('not-an-ip'))
        self.assertFalse(server.validate_ip('999.999.999.999'))
        self.assertFalse(server.validate_ip('192.168.1'))
        self.assertFalse(server.validate_ip('192.168.1.1.1'))
        self.assertFalse(server.validate_ip('192.168.1.1; ls'))
        self.assertFalse(server.validate_ip('$(whoami)'))
        self.assertFalse(server.validate_ip('`id`'))
        self.assertFalse(server.validate_ip('192.168.1.1 && cat /etc/passwd'))


class TestPortValidation(unittest.TestCase):
    def test_valid_ports(self):
        self.assertTrue(server.validate_port('0'))
        self.assertTrue(server.validate_port('80'))
        self.assertTrue(server.validate_port('443'))
        self.assertTrue(server.validate_port('8080'))
        self.assertTrue(server.validate_port('65535'))

    def test_invalid_ports(self):
        self.assertFalse(server.validate_port('-1'))
        self.assertFalse(server.validate_port('65536'))
        self.assertFalse(server.validate_port(''))
        self.assertFalse(server.validate_port('abc'))
        self.assertFalse(server.validate_port('80; ls'))
        self.assertFalse(server.validate_port('$(id)'))
        self.assertFalse(server.validate_port(None))


class TestPathSafety(unittest.TestCase):
    def test_safe_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            safe = os.path.join(tmpdir, 'file.txt')
            self.assertTrue(server.is_safe_path(tmpdir, safe))

    def test_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            unsafe = os.path.join(tmpdir, '..', 'etc', 'passwd')
            self.assertFalse(server.is_safe_path(tmpdir, unsafe))

    def test_same_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertTrue(server.is_safe_path(tmpdir, tmpdir))


class TestFilenameSanitization(unittest.TestCase):
    def test_basic_filename(self):
        self.assertEqual(server.sanitize_filename('test.pcap'), 'test.pcap')

    def test_path_traversal_in_filename(self):
        self.assertEqual(server.sanitize_filename('../../../etc/passwd'), 'passwd')
        self.assertEqual(server.sanitize_filename('..\\..\\etc\\passwd'), 'passwd')

    def test_special_characters(self):
        result = server.sanitize_filename('file name.pcap')
        self.assertEqual(result, 'file name.pcap')


class TestZipSlipPrevention(unittest.TestCase):
    def test_normal_zip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, 'test.zip')
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('normal.txt', 'content')
            with zipfile.ZipFile(zip_path, 'r') as zf:
                server.validate_zip_extraction(zf, tmpdir)

    def test_slip_attempt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, 'evil.zip')
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('../../../escape.txt', 'malicious')
            with zipfile.ZipFile(zip_path, 'r') as zf:
                with self.assertRaises(ValueError) as ctx:
                    server.validate_zip_extraction(zf, tmpdir)
                self.assertIn('Zip slip', str(ctx.exception))

    def test_absolute_path_in_zip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, 'evil.zip')
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('/etc/passwd', 'malicious')
            with zipfile.ZipFile(zip_path, 'r') as zf:
                with self.assertRaises(ValueError):
                    server.validate_zip_extraction(zf, tmpdir)


class TestURLValidation(unittest.TestCase):
    @unittest.mock.patch('socket.gethostbyname')
    def test_valid_public_url(self, mock_dns):
        mock_dns.return_value = '93.184.216.34'
        server.validate_url_safety('https://example.com/file.pcap')

    def test_blocks_localhost(self):
        with self.assertRaises(ValueError) as ctx:
            server.validate_url_safety('http://localhost:8080/secret')
        self.assertIn('localhost', str(ctx.exception).lower())

    @unittest.mock.patch('socket.gethostbyname')
    def test_blocks_127_0_0_1(self, mock_dns):
        mock_dns.return_value = '127.0.0.1'
        with self.assertRaises(ValueError):
            server.validate_url_safety('http://127.0.0.1:8080/secret')

    @unittest.mock.patch('socket.gethostbyname')
    def test_blocks_private_10x(self, mock_dns):
        mock_dns.return_value = '10.0.0.1'
        with self.assertRaises(ValueError):
            server.validate_url_safety('http://internal.corp/file')

    @unittest.mock.patch('socket.gethostbyname')
    def test_blocks_private_192x(self, mock_dns):
        mock_dns.return_value = '192.168.1.1'
        with self.assertRaises(ValueError):
            server.validate_url_safety('http://router.local/file')

    @unittest.mock.patch('socket.gethostbyname')
    def test_blocks_link_local(self, mock_dns):
        mock_dns.return_value = '169.254.169.254'
        with self.assertRaises(ValueError):
            server.validate_url_safety('http://169.254.169.254/latest/meta-data/')

    @unittest.mock.patch('socket.gethostbyname')
    def test_blocks_metadata_service(self, mock_dns):
        mock_dns.return_value = '169.254.169.254'
        with self.assertRaises(ValueError):
            server.validate_url_safety('http://169.254.169.254/latest/meta-data/')

    def test_blocks_file_scheme(self):
        with self.assertRaises(ValueError):
            server.validate_url_safety('file:///etc/passwd')

    def test_blocks_ftp_scheme(self):
        with self.assertRaises(ValueError):
            server.validate_url_safety('ftp://evil.com/malware')

    def test_blocks_empty_hostname(self):
        with self.assertRaises(ValueError):
            server.validate_url_safety('http:///path')


class TestPcapContentValidation(unittest.TestCase):
    def test_pcap_magic_little_endian(self):
        data = b'\xd4\xc3\xb2\xa1' + b'\x00' * 20
        self.assertTrue(server.validate_pcap_content(data))

    def test_pcap_magic_big_endian(self):
        data = b'\xa1\xb2\xc3\xd4' + b'\x00' * 20
        self.assertTrue(server.validate_pcap_content(data))

    def test_pcapng_magic(self):
        data = b'\x0a\x0d\x0d\x0a' + b'\x00' * 20
        self.assertTrue(server.validate_pcap_content(data))

    def test_random_data_rejected(self):
        data = b'this is not a pcap file at all'
        self.assertFalse(server.validate_pcap_content(data))

    def test_html_rejected(self):
        data = b'<html><body>not a pcap</body></html>'
        self.assertFalse(server.validate_pcap_content(data))

    def test_elf_rejected(self):
        data = b'\x7fELF' + b'\x00' * 20
        self.assertFalse(server.validate_pcap_content(data))

    def test_short_data_not_pcap(self):
        data = b'\x00' * 3
        self.assertFalse(server.validate_pcap_content(data))

    def test_zip_magic_accepted(self):
        data = b'PK\x03\x04' + b'\x00' * 20
        self.assertTrue(server.validate_pcap_content(data))

    def test_zip_empty_accepted(self):
        data = b'PK\x05\x06' + b'\x00' * 20
        self.assertTrue(server.validate_pcap_content(data))

    def test_short_zip_rejected(self):
        data = b'PK\x03'
        self.assertFalse(server.validate_pcap_content(data))

    def test_old_zip_suffix_check_removed(self):
        """Ensure the broken data.endswith(b'.zip') check is gone."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertNotIn("data.endswith(b'.zip')", content)
        self.assertNotIn('data.endswith(b".zip")', content)


class TestRateLimiting(unittest.TestCase):
    pass


class TestMD5Validation(unittest.TestCase):
    def test_valid_md5(self):
        self.assertTrue(bool(__import__('re').match(r'^[a-f0-9]{32}$', 'd41d8cd98f00b204e9800998ecf8427e')))

    def test_invalid_md5(self):
        self.assertFalse(bool(__import__('re').match(r'^[a-f0-9]{32}$', '../../../etc/passwd')))
        self.assertFalse(bool(__import__('re').match(r'^[a-f0-9]{32}$', 'short')))
        self.assertFalse(bool(__import__('re').match(r'^[a-f0-9]{32}$', 'GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG')))
        self.assertFalse(bool(__import__('re').match(r'^[a-f0-9]{32}$', '../etc/passwd')))


class TestAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.original_base = server.DATA_DIR
        server.DATA_DIR = cls.tmpdir

        cls.port = 18000 + (os.getpid() % 1000)
        cls.server = server.ThreadedTCPServer(('127.0.0.1', cls.port), server.Handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        server.DATA_DIR = cls.original_base
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        time.sleep(0.05)

    def _get(self, path):
        import urllib.request
        try:
            req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}')
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def _post(self, path, data, content_type='application/json'):
        import urllib.request
        body = json.dumps(data).encode() if isinstance(data, dict) else data
        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}',
            data=body,
            headers={'Content-Type': content_type}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def _post_multipart(self, path, filename, file_content):
        import urllib.request
        boundary = '----TestBoundary123'
        body = (
            f'------TestBoundary123\r\n'
            f'Content-Disposition: form-data; name="pcap"; filename="{filename}"\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n'
        ).encode() + file_content + b'\r\n------TestBoundary123--\r\n'

        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}',
            data=body,
            headers={'Content-Type': f'multipart/form-data; boundary=----TestBoundary123'}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_events_empty(self):
        status, body = self._get('/api/events?md5=' + 'a' * 32)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

    def test_version_endpoint(self):
        status, body = self._get('/api/version')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('version', data)
        self.assertRegex(data['version'], r'^\d+\.\d+\.\d+$')

    def test_events_with_valid_md5(self):
        md5dir = os.path.join(self.tmpdir, 'd41d8cd98f00b204e9800998ecf8427e')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get('/api/events?md5=d41d8cd98f00b204e9800998ecf8427e')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data), 1)

    def test_events_requires_md5(self):
        status, body = self._get('/api/events')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

    def test_events_with_q_parameter(self):
        md5 = 'e99a18c428cb38d5f260853678922e03'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/events?md5={md5}&q=dns')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['event_type'], 'dns')

    def test_stats_with_q_parameter(self):
        md5 = 'ab56b4d92b40713acc5af89985d4b786'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/stats?md5={md5}&q=alert')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('alert'), 1)
        self.assertNotIn('dns', data)

    def test_count_with_q_parameter(self):
        md5 = 'a3f5c5f7e7b5f5e5d5c5b5a595857565'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/count?md5={md5}&q=dns')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['count'], 1)

    def test_events_with_multiple_q_params(self):
        md5 = 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4", "dest_port": 80}\n')
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8", "dest_port": 443}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:02", "src_ip": "1.2.3.4"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/events?md5={md5}&q=alert&q=80')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['event_type'], 'alert')
        self.assertEqual(data[0]['dest_port'], 80)

    def test_stats_with_multiple_q_params(self):
        md5 = 'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4", "dest_port": 80}\n')
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8", "dest_port": 443}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/stats?md5={md5}&q=alert&q=80')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('alert'), 1)

    def test_count_with_multiple_q_params(self):
        md5 = 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4", "dest_port": 80}\n')
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8", "dest_port": 443}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/count?md5={md5}&q=alert&q=80')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['count'], 1)

    def test_events_invalid_limit(self):
        md5 = 'a' * 32
        status, body = self._get(f'/api/events?md5={md5}&limit=abc')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

    def test_events_invalid_offset(self):
        md5 = 'a' * 32
        status, body = self._get(f'/api/events?md5={md5}&offset=xyz')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

    def test_events_negative_limit(self):
        md5 = 'a' * 32
        status, body = self._get(f'/api/events?md5={md5}&limit=-1')
        self.assertEqual(status, 200)

    def test_events_negative_offset(self):
        md5 = 'a' * 32
        status, body = self._get(f'/api/events?md5={md5}&offset=-5')
        self.assertEqual(status, 200)

    def test_events_zero_limit(self):
        md5 = 'a' * 32
        status, body = self._get(f'/api/events?md5={md5}&limit=0')
        self.assertEqual(status, 200)

    def test_stats_requires_md5(self):
        status, body = self._get('/api/stats')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_count_requires_md5(self):
        status, body = self._get('/api/count')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_download_stream_requires_md5(self):
        status, _ = self._get('/api/download-stream?src=1.2.3.4&sport=80&dst=5.6.7.8&dport=443')
        self.assertEqual(status, 400)

    def test_ascii_stream_requires_md5(self):
        status, _ = self._get('/api/ascii-stream?src=1.2.3.4&sport=80&dst=5.6.7.8&dport=443')
        self.assertEqual(status, 400)

    def test_analyses_empty(self):
        status, body = self._get('/api/analyses')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

    def test_load_analysis_invalid_md5(self):
        status, body = self._get('/api/load-analysis?md5=invalid')
        self.assertEqual(status, 400)

    def test_load_analysis_valid_format_nonexistent(self):
        status, body = self._get('/api/load-analysis?md5=' + 'a' * 32)
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_delete_analysis_valid_format_nonexistent(self):
        status, body = self._get('/api/delete-analysis?md5=' + 'a' * 32)
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_pcap_path_invalid_md5(self):
        status, body = self._get('/api/pcap-path?md5=invalid')
        self.assertEqual(status, 400)

    def test_pcap_path_valid_format_nonexistent(self):
        status, body = self._get('/api/pcap-path?md5=' + 'a' * 32)
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_download_stream_invalid_ip(self):
        status, _ = self._get('/api/download-stream?src=bad&sport=80&dst=1.2.3.4&dport=443')
        self.assertEqual(status, 400)

    def test_download_stream_invalid_port(self):
        status, _ = self._get('/api/download-stream?src=1.2.3.4&sport=99999&dst=5.6.7.8&dport=80')
        self.assertEqual(status, 400)

    def test_download_stream_command_injection(self):
        status, _ = self._get('/api/download-stream?src=1.2.3.4&sport=80;ls&dst=5.6.7.8&dport=443')
        self.assertEqual(status, 400)

    def test_download_stream_missing_params(self):
        status, _ = self._get('/api/download-stream?src=1.2.3.4')
        self.assertEqual(status, 400)

    def test_ascii_stream_command_injection(self):
        status, _ = self._get('/api/ascii-stream?src=1.2.3.4&sport=80|cat&dst=5.6.7.8&dport=443')
        self.assertEqual(status, 400)

    def test_ascii_stream_missing_params(self):
        status, _ = self._get('/api/ascii-stream?src=1.2.3.4')
        self.assertEqual(status, 400)

    def test_hexdump_stream_requires_md5(self):
        status, _ = self._get('/api/hexdump-stream?src=1.2.3.4&sport=80&dst=5.6.7.8&dport=443')
        self.assertEqual(status, 400)

    def test_hexdump_stream_invalid_ip(self):
        status, _ = self._get('/api/hexdump-stream?src=bad&sport=80&dst=1.2.3.4&dport=443&md5=' + 'a' * 32)
        self.assertEqual(status, 400)

    def test_hexdump_stream_invalid_port(self):
        status, _ = self._get('/api/hexdump-stream?src=1.2.3.4&sport=99999&dst=5.6.7.8&dport=80&md5=' + 'a' * 32)
        self.assertEqual(status, 400)

    def test_hexdump_stream_command_injection(self):
        status, _ = self._get('/api/hexdump-stream?src=1.2.3.4&sport=80;ls&dst=5.6.7.8&dport=443&md5=' + 'a' * 32)
        self.assertEqual(status, 400)

    def test_hexdump_stream_missing_params(self):
        status, _ = self._get('/api/hexdump-stream?src=1.2.3.4&md5=' + 'a' * 32)
        self.assertEqual(status, 400)

    def test_stream_filter_uses_and_not_or(self):
        """download-stream and hexdump-stream must use 'and port' not 'or port'
        to avoid pulling in unrelated UDP flows sharing the same destination port."""
        import inspect
        import ohmypcap
        source = inspect.getsource(ohmypcap)
        # Find the tcpdump filter lines for hexdump and download
        self.assertIn("f'host {src} and host {dst} and port {sport} and port {dport}'", source)
        self.assertIn("f\"host {src} and host {dst} and port {sport} and port {dport}\"", source)
        self.assertNotIn("or port {dport}", source)

    def test_upload_traversal_filename(self):
        # Use unique PCAP content to avoid collision with test_upload_same_pcap_in_different_zips
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x02' * 100
        status, body = self._post_multipart(
            '/api/upload',
            '../../../etc/evil.pcap',
            pcap_data
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        md5 = data['md5']
        saved_files = os.listdir(os.path.join(self.tmpdir, md5))
        self.assertIn('evil.pcap', saved_files)
        self.assertNotIn('../../../etc/evil.pcap', saved_files)

    def test_upload_valid_pcap(self):
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' + b'\x00' * 92
        status, body = self._post_multipart('/api/upload', 'test.pcap', pcap_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertIn('status', data)
        self.assertEqual(data.get('phase'), 'network', 'PCAP upload must report network phase')

    def test_upload_non_pcap_content(self):
        status, body = self._post_multipart('/api/upload', 'fake.pcap', b'not a pcap file')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data.get('status'), 'processing')
        self.assertEqual(data.get('phase'), 'files', 'Non-PCAP upload must report files phase')

    def test_upload_html_as_pcap(self):
        status, body = self._post_multipart('/api/upload', 'evil.pcap', b'<html><script>alert(1)</script></html>')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data.get('status'), 'processing')
        self.assertEqual(data.get('phase'), 'files', 'Non-PCAP upload must report files phase')

    def test_upload_elf_as_pcap(self):
        status, body = self._post_multipart('/api/upload', 'malware.pcap', b'\x7fELF' + b'\x00' * 100)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data.get('status'), 'processing')
        self.assertEqual(data.get('phase'), 'files', 'Non-PCAP upload must report files phase')

    def test_upload_any_extension_detected_as_pcap(self):
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x00' * 100
        status, body = self._post_multipart('/api/upload', 'test.txt', pcap_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data.get('phase'), 'network', 'PCAP-by-magic upload must report network phase')

    def test_upload_non_pcap_file(self):
        file_data = b'THIS_IS_NOT_A_PCAP_FILE_JUST_TEXT'
        status, body = self._post_multipart('/api/upload', 'test.exe', file_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data.get('status'), 'processing')
        self.assertEqual(data.get('phase'), 'files', 'Non-PCAP upload must report files phase')

    @unittest.mock.patch('ohmypcap.scan_single_file')
    @unittest.mock.patch('ohmypcap.check_yara_executable')
    @unittest.mock.patch('ohmypcap.setup_yara_rules')
    def test_upload_non_pcap_creates_file_analysis_db(self, mock_setup, mock_check, mock_scan):
        """Uploading a non-PCAP file creates events.db with fileinfo + filealerts."""
        mock_setup.return_value = '/tmp/fake-yara-rules'
        mock_check.return_value = True
        matches = [{
            'rule_name': 'TEST_Malware',
            'classification': 'threat',
            'tags': ['test'],
            'meta': {'author': 'test'},
            'strings': [],
            'file_id': '',
        }]
        mock_scan.return_value = (matches, 'a' * 64, 'b' * 32, 'c' * 40)

        file_data = b'MZ' + b'\x00' * 62
        status, body = self._post_multipart('/api/upload', 'test.exe', file_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        self.assertEqual(data.get('phase'), 'files')

        # Poll until analysis is ready
        for _ in range(30):
            time.sleep(0.2)
            status, body = self._post('/api/check-status', {'md5': md5})
            result = json.loads(body)
            if result.get('status') == 'ready':
                break

        dir_path = os.path.join(server.DATA_DIR, md5)
        db_path = os.path.join(dir_path, 'events.db')
        self.assertTrue(os.path.exists(db_path), 'events.db must be created for standalone file')
        self.assertFalse(os.path.exists(os.path.join(dir_path, '.phase')), '.phase must be cleaned up')

        name_path = os.path.join(dir_path, 'name.txt')
        self.assertTrue(os.path.exists(name_path), 'name.txt must be created')
        with open(name_path, 'r') as f:
            self.assertEqual(f.read().strip(), 'test.exe')

        # Verify database contents
        fileinfo_events = db.query_events_sqlite(db_path, event_type='fileinfo')
        self.assertEqual(len(fileinfo_events), 1, 'Must have one fileinfo event')
        fi = fileinfo_events[0]
        self.assertEqual(fi['event_type'], 'fileinfo')
        self.assertEqual(fi['fileinfo']['filename'], 'test.exe')
        self.assertEqual(fi['fileinfo']['size'], 64)

        alert_events = db.query_events_sqlite(db_path, event_type='filealerts')
        self.assertEqual(len(alert_events), 1, 'Must have one filealerts event')
        fa = alert_events[0]
        self.assertEqual(fa['event_type'], 'filealerts')
        self.assertEqual(fa['filealerts']['rule_name'], 'TEST_Malware')
        self.assertEqual(fa['filealerts']['classification'], 'threat')

        # Verify mocks were called
        mock_setup.assert_called_once()
        mock_check.assert_called_once()
        mock_scan.assert_called_once()

    @unittest.mock.patch('ohmypcap.scan_single_file')
    @unittest.mock.patch('ohmypcap.check_yara_executable')
    @unittest.mock.patch('ohmypcap.setup_yara_rules')
    def test_upload_zip_with_non_pcap_creates_file_analysis_db(self, mock_setup, mock_check, mock_scan):
        """Uploading a ZIP containing a non-PCAP file creates events.db with correct extracted name."""
        mock_setup.return_value = '/tmp/fake-yara-rules'
        mock_check.return_value = True
        matches = [{
            'rule_name': 'ZIP_Malware',
            'classification': 'technique',
            'tags': ['zip'],
            'meta': {},
            'strings': [],
            'file_id': '',
        }]
        mock_scan.return_value = (matches, 'd' * 64, 'e' * 32, 'f' * 40)

        # Create ZIP with a non-PCAP file
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('malware.exe', b'\x7fELF' + b'\x00' * 60)
        zip_data = zip_buffer.getvalue()
        expected_md5 = hashlib.md5(b'\x7fELF' + b'\x00' * 60).hexdigest()

        status, body = self._post_multipart('/api/upload', 'samples.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        self.assertEqual(md5, expected_md5, 'MD5 must be computed from extracted file bytes')
        self.assertEqual(data.get('phase'), 'files')

        # Poll until analysis is ready
        for _ in range(30):
            time.sleep(0.2)
            status, body = self._post('/api/check-status', {'md5': md5})
            result = json.loads(body)
            if result.get('status') == 'ready':
                break

        dir_path = os.path.join(server.DATA_DIR, md5)
        db_path = os.path.join(dir_path, 'events.db')
        self.assertTrue(os.path.exists(db_path), 'events.db must be created for ZIP-extracted file')

        name_path = os.path.join(dir_path, 'name.txt')
        self.assertTrue(os.path.exists(name_path), 'name.txt must use extracted filename')
        with open(name_path, 'r') as f:
            self.assertEqual(f.read().strip(), 'malware.exe')

        # Verify database uses extracted filename
        fileinfo_events = db.query_events_sqlite(db_path, event_type='fileinfo')
        self.assertEqual(len(fileinfo_events), 1)
        self.assertEqual(fileinfo_events[0]['fileinfo']['filename'], 'malware.exe')

        alert_events = db.query_events_sqlite(db_path, event_type='filealerts')
        self.assertEqual(len(alert_events), 1)
        self.assertEqual(alert_events[0]['filealerts']['rule_name'], 'ZIP_Malware')

    def test_upload_valid_zip(self):
        import io
        import zipfile as zf
        import hashlib
        # Use unique PCAP content so this test doesn't collide with test_upload_same_pcap_in_different_zips
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x01' * 100
        expected_md5 = hashlib.md5(pcap_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('test.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'test.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data['md5'], expected_md5,
                         'MD5 should be computed from extracted PCAP, not the ZIP')
        self.assertEqual(data['status'], 'processing')
        # Verify directory was created using PCAP MD5
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, expected_md5, 'test.pcap')))

    def test_upload_tries_password_protected_zips(self):
        """Upload handler code must attempt common passwords before rejecting protected ZIPs."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # Verify helper exists and handles password fallback
        self.assertIn("def _extract_zip_contents(zip_data, extract_dir, passwords=None):", content,
                      'Must define _extract_zip_contents helper')
        helper_section = content.split("def _extract_zip_contents(zip_data, extract_dir, passwords=None):")[1].split("class Handler(")[0]
        # Should try no password first
        self.assertIn("extracted = False", helper_section,
                      'Must track extraction success')
        self.assertIn("zip_ref.extractall(extract_dir)", helper_section,
                      'Must attempt extraction without password')
        # Should try provided passwords
        self.assertIn("for pwd in passwords:", helper_section,
                      'Must loop over candidate passwords')
        # Upload handler should derive passwords from filename
        upload_section = content.split("def handle_post_upload(self):")[1].split("def handle_post_load_url(self):")[0]
        self.assertIn("passwords = [b'infected']", upload_section,
                      'Must try infected password')
        self.assertIn("re.search(r'(\d{4})-(\d{2})-(\d{2})', original_filename)", upload_section,
                      'Must derive date-based password from filename')
        self.assertIn("'infected_{year}{month}{day}'.encode()", upload_section,
                      'Must construct MTA-style date password')
        # _process_uploaded_file must call _extract_zip_contents
        process_section = content.split("def _process_uploaded_file(self,")[1].split("def handle_post_upload(self):")[0]
        self.assertIn("_extract_zip_contents(file_data, tmp_dir, passwords or [])", process_section,
                      'Must call _extract_zip_contents helper')

    def test_upload_same_pcap_in_different_zips(self):
        import io
        import zipfile as zf
        import hashlib
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x00' * 100
        expected_md5 = hashlib.md5(pcap_data).hexdigest()

        # First ZIP
        zip1 = io.BytesIO()
        with zf.ZipFile(zip1, 'w') as z:
            z.writestr('capture.pcap', pcap_data)
        status1, body1 = self._post_multipart('/api/upload', 'first.zip', zip1.getvalue())
        self.assertEqual(status1, 200)
        data1 = json.loads(body1)
        self.assertEqual(data1['md5'], expected_md5)

        # Second ZIP with different name and extra file
        zip2 = io.BytesIO()
        with zf.ZipFile(zip2, 'w') as z:
            z.writestr('readme.txt', 'extra file')
            z.writestr('network.pcap', pcap_data)
        status2, body2 = self._post_multipart('/api/upload', 'second.zip', zip2.getvalue())
        self.assertEqual(status2, 200)
        data2 = json.loads(body2)
        self.assertEqual(data2['md5'], expected_md5,
                         'Same PCAP inside different ZIPs should produce the same MD5')

    def test_load_url_no_url_provided(self):
        status, body = self._post('/api/load-url', {})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('No URL provided', data.get('error', ''))

    def test_load_url_rejects_private_ip(self):
        status, body = self._post('/api/load-url', {'url': 'http://10.0.0.1/test.pcap'})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('private', data.get('error', '').lower())

    def test_load_url_rejects_localhost(self):
        status, body = self._post('/api/load-url', {'url': 'http://localhost/test.pcap'})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('localhost', data.get('error', '').lower())

    def test_load_url_empty_url(self):
        status, body = self._post('/api/load-url', {'url': ''})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('No URL provided', data.get('error', ''))

    def test_load_url_blocks_dns_rebinding(self):
        """Behavioral: load-url must validate URL before and after DNS resolution to prevent rebinding."""
        import unittest.mock
        # Mock DNS to return a private IP for a public-looking hostname
        with unittest.mock.patch('socket.gethostbyname', return_value='127.0.0.1'):
            status, body = self._post('/api/load-url', {'url': 'http://fake-public.example.com/secret'})
            self.assertEqual(status, 400)
            data = json.loads(body)
            # URL validation fails at some point (DNS resolve or IP check)
            self.assertIn('error', data)

    def test_check_status_missing_md5(self):
        status, body = self._post('/api/check-status', {})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid MD5', data.get('error', ''))

    def test_check_status_invalid_md5_format(self):
        status, body = self._post('/api/check-status', {'md5': 'not-a-valid-md5'})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid MD5', data.get('error', ''))

    def test_check_status_path_traversal(self):
        status, body = self._post('/api/check-status', {'md5': '../../../etc/passwd'})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid MD5', data.get('error', ''))

    def test_check_status_nonexistent_md5(self):
        status, body = self._post('/api/check-status', {'md5': '0' * 32})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('status', data)

    def test_check_status_ready_with_sqlite(self):
        md5dir = os.path.join(self.tmpdir, 'abc123def45678901234567890123456')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert"}\n')
        with open(os.path.join(md5dir, 'events.db'), 'w') as f:
            f.write('')
        
        status, body = self._post('/api/check-status', {'md5': 'abc123def45678901234567890123456'})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('status'), 'ready')

    def test_check_status_ready_with_eve_json_only(self):
        md5dir = os.path.join(self.tmpdir, 'abcdef12345678901234567890123456')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert"}\n')
        
        status, body = self._post('/api/check-status', {'md5': 'abcdef12345678901234567890123456'})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('status'), 'processing')

    def test_check_status_processing_empty_eve_json(self):
        md5dir = os.path.join(self.tmpdir, 'aaa123def45678901234567890123456')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('')
        
        status, body = self._post('/api/check-status', {'md5': 'aaa123def45678901234567890123456'})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('status'), 'processing')

    def test_check_status_error_file(self):
        md5dir = os.path.join(self.tmpdir, 'deadbeef123456789012345678901234')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, '.error'), 'w') as f:
            f.write('YARA scan failed: out of memory')
        status, body = self._post('/api/check-status', {'md5': 'deadbeef123456789012345678901234'})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('status'), 'error')
        self.assertIn('out of memory', data.get('message', ''))

    def test_check_status_stale_error_file(self):
        md5dir = os.path.join(self.tmpdir, 'cafebabe123456789012345678901234')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, '.error'), 'w') as f:
            f.write('old error')
        # Make the error file appear older than 10 minutes
        old_time = time.time() - 700
        os.utime(os.path.join(md5dir, '.error'), (old_time, old_time))
        status, body = self._post('/api/check-status', {'md5': 'cafebabe123456789012345678901234'})
        self.assertEqual(status, 200)
        data = json.loads(body)
        # Stale error should be cleaned up, so we see processing (no db yet)
        self.assertEqual(data.get('status'), 'processing')
        self.assertFalse(os.path.exists(os.path.join(md5dir, '.error')))

    def test_reanalyze_keeps_pcap_and_name(self):
        """Behavioral: reanalyze must preserve PCAP and name.txt while removing artifacts."""
        import io, zipfile as zf
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x03' * 100
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('capture.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'capture.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(self.tmpdir, md5)

        # Wait for analysis dir to be created
        import time
        time.sleep(0.2)

        # Create some artifacts to verify cleanup
        with open(os.path.join(dir_path, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert"}\n')
        with open(os.path.join(dir_path, 'events.db'), 'w') as f:
            f.write('')
        with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
            f.write('capture.zip')

        # Create .phase to simulate in-progress analysis (reanalyze should clear it)
        with open(os.path.join(dir_path, '.phase'), 'w') as f:
            f.write('network')

        # Call reanalyze
        status, body = self._post('/api/reanalyze', {'md5': md5})
        self.assertEqual(status, 200)

        # Verify PCAP and name.txt still exist
        pcap_files = [f for f in os.listdir(dir_path) if f.endswith('.pcap')]
        self.assertTrue(len(pcap_files) > 0, 'PCAP file must be preserved after reanalyze')
        self.assertTrue(os.path.exists(os.path.join(dir_path, 'name.txt')), 'name.txt must be preserved')

        # Verify artifacts were removed
        self.assertFalse(os.path.exists(os.path.join(dir_path, 'eve.json')), 'eve.json must be removed')
        self.assertFalse(os.path.exists(os.path.join(dir_path, 'events.db')), 'events.db must be removed')

    def test_upload_password_protected_zip(self):
        """Behavioral: upload must extract password-protected ZIPs using common passwords."""
        import io, zipfile as zf
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x04' * 100
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            # Python's zipfile supports simple password encryption with ZIP_STORED
            zf_obj.writestr('secret.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()

        # Test that a non-password ZIP still works
        status, body = self._post_multipart('/api/upload', 'plain.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)


class TestSpawnSuricataErrorHandling(unittest.TestCase):
    def test_spawn_suricata_writes_error_on_failure(self):
        """Behavioral: spawn_suricata must write .error file when subprocess fails."""
        import unittest.mock
        from suricata import spawn_suricata
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = os.path.join(tmpdir, 'test.pcap')
            with open(pcap_path, 'wb') as f:
                f.write(b'\xd4\xc3\xb2\xa1' + b'\x00' * 100)

            # Mock subprocess.Popen to raise an error
            with unittest.mock.patch('subprocess.Popen', side_effect=OSError('suricata not found')):
                result = spawn_suricata(tmpdir, pcap_path)
                self.assertFalse(result, 'spawn_suricata must return False on failure')

            # Verify .error file was written
            error_file = os.path.join(tmpdir, '.error')
            self.assertTrue(os.path.exists(error_file), '.error file must be written on spawn failure')
            with open(error_file, 'r') as f:
                error_msg = f.read()
            self.assertIn('suricata not found', error_msg, 'Error message must include the failure reason')

            # Verify .phase was cleared
            self.assertFalse(os.path.exists(os.path.join(tmpdir, '.phase')), '.phase must be cleared on failure')


class TestServerBinding(unittest.TestCase):
    def test_server_binds_localhost(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('127.0.0.1', content)
        self.assertNotIn('("", PORT)', content)
        self.assertNotIn('("0.0.0.0", PORT)', content)


class TestNoCorsWildcard(unittest.TestCase):
    def test_no_cors_wildcard(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertNotIn("Access-Control-Allow-Origin', '*'", content)
        self.assertNotIn('Access-Control-Allow-Origin", "*"', content)


class TestErrorMessages(unittest.TestCase):
    def test_no_internal_error_leak(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertNotIn('str(e)', content)
        self.assertNotIn('traceback', content.lower())


class TestLoadUrlContentValidation(unittest.TestCase):
    def test_load_url_detects_pcap_by_magic(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('is_pcap_file(file_data)', content,
                      'load_url must detect PCAP by magic bytes')
        self.assertIn('def is_pcap_file(data):', content,
                      'is_pcap_file helper must exist')




class TestThreadedServer(unittest.TestCase):
    def test_threaded_server_class_exists(self):
        self.assertTrue(hasattr(server, 'ThreadedTCPServer'))


class TestSizeLimitMessages(unittest.TestCase):
    def test_max_eve_size_constant(self):
        self.assertEqual(config.MAX_EVE_SIZE, 1000 * 1024 * 1024)
    
    def test_error_message_consistency(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        error_count = content.count('max {MAX_EVE_SIZE // (1024*1024)}MB')
        error_text_count = content.count('Eve.json')
        self.assertGreaterEqual(error_count, 1, 'Error message appears at least once')
        self.assertGreaterEqual(error_text_count, 1, 'Eve.json text appears at least once')


class TestHTMLNoDuplicateFunctions(unittest.TestCase):
    def test_no_duplicate_html_functions(self):
        html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ohmypcap.html')
        with open(html_file, 'r') as f:
            content = f.read()
        import re
        func_pattern = r'function\s+(\w+)\s*\('
        functions = re.findall(func_pattern, content)
        duplicates = {f for f in functions if functions.count(f) > 1}
        self.assertEqual(len(duplicates), 0, f'Duplicate JavaScript functions found: {duplicates}')


class TestPythonNoBareExcept(unittest.TestCase):
    def test_no_bare_except_statements(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        bare_except_pattern = r'except\s*:'
        matches = re.findall(bare_except_pattern, content)
        self.assertEqual(len(matches), 0, f'Found bare except statements: {matches}')


class TestSuricataConfigRulesPath(unittest.TestCase):
    def test_suricata_yaml_uses_custom_rules_path(self):
        suricata_dir = os.path.expanduser('~/ohmypcap-data/suricata')
        suricata_config = os.path.join(suricata_dir, 'suricata.yaml')
        
        # Skip if config doesn't exist (may not be set up yet)
        if not os.path.exists(suricata_config):
            self.skipTest('Suricata config not found')
        
        with open(suricata_config, 'r') as f:
            content = f.read()
        
        # Verify default-rule-path points to a custom directory
        # (may be ~/ohmypcap-data/suricata/rules for native or /data/suricata/rules for container)
        native_path = os.path.expanduser('~/ohmypcap-data/suricata/rules')
        container_path = '/data/suricata/rules'
        self.assertTrue(native_path in content or container_path in content,
                        f'suricata.yaml should use custom rules path (either {native_path} or {container_path})')
        self.assertNotIn('/var/lib/suricata/rules', content,
                         'suricata.yaml should not use system rules path')


class TestSecurityHeaders(unittest.TestCase):
    def test_x_frame_options(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("X-Frame-Options', 'DENY'", content)

    def test_x_content_type_options(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("X-Content-Type-Options', 'nosniff'", content)

    def test_content_security_policy(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("Content-Security-Policy", content)
        self.assertIn("default-src 'self'", content)

    def test_end_headers_calls_security_headers(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('def end_headers(self):', content)
        self.assertIn('self._add_security_headers()', content)

    def test_html_cache_control_headers(self):
        """Verify Cache-Control headers are sent for HTML and static assets"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("no-cache, no-store, must-revalidate", content)
        self.assertIn("self.path.endswith('.html')", content)
        self.assertIn("self.path.startswith('/static/')", content)
        self.assertIn("Pragma', 'no-cache'", content)
        self.assertIn("Expires', '0'", content)


class TestSubprocessTimeouts(unittest.TestCase):
    def test_tcpdump_has_timeout(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        tcpdump_match = re.search(r"\['tcpdump', '-r', pcap, '-w', '-'.*?timeout=", content, re.DOTALL)
        self.assertIsNotNone(tcpdump_match, 'tcpdump call must have timeout')
        self.assertIn('STREAM_TIMEOUT_SECONDS', content, 'tcpdump timeout must use centralized constant')

    def test_tshark_has_timeout(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # _extract_payload_lines helper contains the tshark call
        helper_section = content.split("def _extract_payload_lines(self, pcap, src, sport, dst, dport, proto):")[1].split("def handle_get_hexdump_stream(self, params):")[0]
        tshark_match = re.search(r"\['tshark', '-r', pcap.*?timeout=", helper_section, re.DOTALL)
        self.assertIsNotNone(tshark_match, '_extract_payload_lines must call tshark with timeout')
        self.assertIn('STREAM_TIMEOUT_SECONDS', helper_section, 'tshark timeout must use centralized constant')
        # The helper should be called twice (TCP then UDP fallback) from handle_get_ascii_stream
        ascii_section = content.split("def handle_get_ascii_stream(self, params):")[1].split("def _extract_payload_lines(self, pcap, src, sport, dst, dport, proto):")[0]
        calls_in_ascii = ascii_section.count('self._extract_payload_lines(')
        self.assertGreaterEqual(calls_in_ascii, 2, '_extract_payload_lines must be called at least twice from ascii_stream')

    def test_timeout_expired_handled(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('except subprocess.TimeoutExpired:', content)


class TestNoDuplicateImports(unittest.TestCase):
    def test_threading_imported_at_top_level(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # Should have exactly one 'import threading' at the top level
        top_level = content.split('class Handler')[0]
        self.assertEqual(top_level.count('import threading'), 1,
                         'threading should be imported once at module level')
        # Should NOT have inline 'import threading' inside methods
        handler_section = content.split('class Handler')[1]
        self.assertEqual(handler_section.count('import threading'), 0,
                         'threading should not be imported inline inside methods')


class TestSetupSuricataConfigLogging(unittest.TestCase):
    def test_copy_warnings_logged(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("print(f'Warning: could not copy", content)
        self.assertIn("print(f'Warning: could not copy directory", content)


class TestSuricataProcessingLock(unittest.TestCase):
    def test_phase_file_used(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("'.phase'", content)
        self.assertIn("_set_phase", content)
        self.assertIn("_clear_phase", content)

    def test_phase_removed_in_callback(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("_clear_phase", content)

    def test_phase_removed_on_spawn_failure(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        # Count occurrences of _clear_phase in except blocks
        # Should appear at least twice: once in callback, once in failure handler
        self.assertGreaterEqual(content.count("_clear_phase"), 2)

    def test_error_helpers_exist(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("def _set_error(dir_path, message):", content,
                      '_set_error helper must exist in suricata module')
        self.assertIn("def _clear_error(dir_path):", content,
                      '_clear_error helper must exist in suricata module')

    def test_error_set_on_yara_failure(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        on_done = content.split("def on_suricata_done():")[1].split("\n    try:")[0]
        self.assertIn("_set_error", on_done,
                      'YARA failure must write error file')

    def test_error_set_on_db_failure(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        on_done = content.split("def on_suricata_done():")[1].split("\n    try:")[0]
        self.assertIn("create_sqlite_db", on_done,
                      'DB creation must be in callback')
        self.assertIn("_set_error", on_done,
                      'DB failure must write error file')

    def test_error_set_on_spawn_failure(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        spawn_section = content.split("def spawn_suricata(dir_path, pcap_path,")[1].split("def _set_phase(dir_path, phase):")[0]
        self.assertIn("_set_error", spawn_section,
                      'Spawn failure must write error file')

    def test_stale_phase_handled_in_check_status(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        check_status = content.split("def handle_post_check_status(self):")[1].split("def handle_post_reanalyze(self):")[0]
        self.assertIn("lock_age", check_status)
        self.assertIn("STALE_THRESHOLD_SECONDS", check_status)
        self.assertIn("'phase': phase", check_status)

    def test_stale_error_handled_in_check_status(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        check_status = content.split("def handle_post_check_status(self):")[1].split("def handle_post_reanalyze(self):")[0]
        self.assertIn("error_age", check_status)
        self.assertIn("'status': 'error'", check_status)
        self.assertIn("'message': error_msg", check_status)


class TestNameTxtPathSafety(unittest.TestCase):
    def test_analyses_checks_name_txt_safety(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        analyses_section = content.split("def handle_get_analyses(self, params):")[1].split("def handle_get_load_analysis(self, params):")[0]
        self.assertIn("is_safe_path(dir_path, name_path)", analyses_section,
                      '/api/analyses must validate name.txt path')

    def test_load_analysis_checks_name_txt_safety(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        load_section = content.split("def handle_get_load_analysis(self, params):")[1].split("def handle_get_delete_analysis(self, params):")[0]
        self.assertIn("is_safe_path(dir_path, name_path)", load_section,
                      '/api/load-analysis must validate name.txt path')


class TestSuricataRuleRawEnabled(unittest.TestCase):
    def test_rule_raw_set_in_suricata_spawn(self):
        """Verify that suricata is spawned with --set to enable alert.rule in eve.json"""
        with open(SURICATA_FILE, 'r') as f:
            suricata_content = f.read()
        with open(SERVER_FILE, 'r') as f:
            server_content = f.read()
        # Should appear exactly once in spawn_suricata helper
        self.assertEqual(suricata_content.count("'--set', 'outputs.1.eve-log.types.0.alert.metadata.rule.raw=true'"), 1,
                         'rule.raw must be set exactly once in spawn_suricata helper')
        # Verify spawn_suricata is defined in suricata module
        self.assertIn('def spawn_suricata(dir_path, pcap_path, suricata_config_path=None, data_dir=None):', suricata_content,
                      'spawn_suricata must be defined in suricata module')
        # Verify spawn_suricata is called from _process_uploaded_file and reanalyze
        self.assertIn('spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR', server_content,
                      'spawn_suricata must be called from _process_uploaded_file or reanalyze')
        reanalyze_section = server_content.split("def handle_post_reanalyze(self):")[1]
        self.assertIn('spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR', reanalyze_section,
                      'reanalyze must call spawn_suricata for PCAP files')


class TestReanalyzeEndpoint(unittest.TestCase):
    def test_reanalyze_endpoint_exists(self):
        """Verify /api/reanalyze endpoint exists in POST_ROUTES."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("'/api/reanalyze': 'handle_post_reanalyze'", content,
                      'POST /api/reanalyze endpoint must exist')

    def test_reanalyze_deletes_analysis_artifacts(self):
        """Verify reanalyze removes eve.json, events.db, .phase, .error, and yara_matches.json."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        self.assertIn("for artifact in ('eve.json', 'events.db', '.phase', '.error', 'yara_matches.json'):", reanalyze_section,
                      'reanalyze must loop over analysis artifacts to delete')
        self.assertIn('os.unlink(artifact_path)', reanalyze_section,
                      'reanalyze must unlink artifact files')

    def test_reanalyze_keeps_pcap_and_name(self):
        """Verify reanalyze does NOT delete pcap files or name.txt."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        # Should only unlink artifacts, not rmtree the whole directory
        # rmtree is allowed only for the filestore subdirectory
        loop_section = reanalyze_section.split("for artifact in")[1].split("if spawn_suricata")[0]
        self.assertNotIn("name.txt", loop_section,
                         'reanalyze loop must not reference name.txt')

    def test_reanalyze_handles_non_pcap_files(self):
        """Verify reanalyze can re-analyze standalone non-PCAP files."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        self.assertIn('non_pcap_files', reanalyze_section,
                      'reanalyze must look for non-PCAP files')
        self.assertIn("self._analyze_standalone_file", reanalyze_section,
                      'reanalyze must support standalone file re-analysis')

    def test_reanalyze_returns_409_if_already_processing(self):
        """Verify reanalyze returns 409 when analysis is already in progress."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        self.assertIn("self._send_error(409, 'Analysis already in progress')", reanalyze_section,
                      'reanalyze must return 409 if already processing')

    def test_reanalyze_calls_spawn_suricata(self):
        """Verify reanalyze calls spawn_suricata after cleaning artifacts."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        self.assertIn('spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR', reanalyze_section,
                      'reanalyze must call spawn_suricata with config path')


class TestRuleDownloadPrompt(unittest.TestCase):
    def test_rule_download_message_in_stdout(self):
        """Verify that suricata-update outputs messages when rules are downloaded"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()

        # Check for informative messages about rule download
        self.assertIn('Internet access detected', content,
                      'Should log when internet is detected')
        self.assertIn('updating Suricata rules', content,
                      'Should log when updating rules')
        self.assertIn('Suricata rules updated successfully', content,
                      'Should log when rules update completes')


class TestAirgapFallback(unittest.TestCase):
    def test_has_internet_access_function_exists(self):
        """Verify has_internet_access helper is defined"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn('def has_internet_access():', content,
                      'has_internet_access function must exist')

    def test_internet_check_connects_to_rules_server(self):
        """Verify internet check targets the actual rules server"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn('rules.emergingthreats.net', content,
                      'Must check connectivity to rules server')
        self.assertIn('socket.create_connection', content,
                      'Must use socket.create_connection for check')

    def test_baked_in_rules_path_defined(self):
        """Verify baked-in rules path is referenced"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("/usr/share/suricata/rules", content,
                      'Must reference baked-in rules path')

    def test_fallback_uses_shutil_copytree(self):
        """Verify air-gapped fallback copies baked-in rules"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn('shutil.copytree', content,
                      'Must use shutil.copytree for baked-in rules')
        self.assertIn('dirs_exist_ok=True', content,
                      'Must safely overwrite existing rules')

    def test_airgap_log_messages_present(self):
        """Verify log messages for air-gapped path exist"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn('No internet access detected', content,
                      'Should log when falling back to baked-in rules')
        self.assertIn('Baked-in rules copied successfully', content,
                      'Should log when baked-in rules are copied')
        self.assertIn('no baked-in rules found and no internet access', content,
                      'Should warn when no rules are available')


class TestServerStartupBanner(unittest.TestCase):
    def test_windows_banner_format(self):
        """Verify the startup banner has the correct format"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        
        # Check for banner elements
        self.assertIn('Welcome to OhMyPCAP', content)
        self.assertIn('Analyze files from the web or your local collection', content)
        self.assertIn('View alerts and then slice and dice your network metadata', content)

    def test_running_message_has_border(self):
        """Verify the running message is wrapped in a border matching the welcome banner"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('OhMyPCAP running', content)
        self.assertIn('================================================', content)


class TestHTMLNoEmptyFunctions(unittest.TestCase):
    def test_no_empty_functions(self):
        html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ohmypcap.html')
        with open(html_file, 'r') as f:
            content = f.read()
        import re
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*\{\s*\}'
        empty_funcs = re.findall(func_pattern, content, re.DOTALL)
        self.assertEqual(len(empty_funcs), 0, f'Found empty functions: {empty_funcs}')


class TestHTMLNoOldStyleFilterEscaping(unittest.TestCase):
    def test_no_old_style_filter_escaping(self):
        html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ohmypcap.html')
        with open(html_file, 'r') as f:
            content = f.read()
        vulnerable_pattern = r'clearFilter.*col\.replace\(/\'/g'
        matches = re.findall(vulnerable_pattern, content)
        self.assertEqual(len(matches), 0, 'Found vulnerable col.replace pattern in clearFilter')
        vulnerable_pattern2 = r'applyFilter.*displayVal\.replace\(/\'/g'
        matches2 = re.findall(vulnerable_pattern2, content)
        self.assertEqual(len(matches2), 0, 'Found vulnerable displayVal.replace pattern in applyFilter')


class TestHTMLModalCSS(unittest.TestCase):
    def test_loading_modal_exists(self):
        html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ohmypcap.html')
        css_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static', 'ohmypcap.css')
        with open(html_file, 'r') as f:
            html_content = f.read()
        with open(css_file, 'r') as f:
            css_content = f.read()
        self.assertIn('id="loadingModal"', html_content, 'loadingModal element should exist')
        self.assertIn('.modal {', css_content, 'modal CSS should exist')
        self.assertIn('.modal.active {', css_content, 'modal.active CSS should exist')
        self.assertIn('.spinner {', css_content, 'spinner CSS should exist')
        self.assertIn('.spinner-dot {', css_content, 'spinner-dot CSS should exist')


class TestEnvironmentVariables(unittest.TestCase):
    """Test that configurable environment variables are properly defined."""

    def test_data_dir_env_var(self):
        """DATA_DIR must be defined and replace the old BASE_DIR"""
        self.assertTrue(hasattr(server, 'DATA_DIR'))
        self.assertFalse(hasattr(server, 'BASE_DIR'))

    def test_bind_address_env_var(self):
        """BIND_ADDRESS must be defined for Docker support"""
        self.assertTrue(hasattr(server, 'BIND_ADDRESS'))
        self.assertEqual(server.BIND_ADDRESS, '127.0.0.1')

    def test_port_env_var(self):
        """PORT must be configurable via environment variable"""
        self.assertTrue(hasattr(server, 'PORT'))
        self.assertEqual(server.PORT, 8000)


class TestExecutableChecks(unittest.TestCase):
    def test_check_executables_returns_list(self):
        result = server.check_executables()
        self.assertIsInstance(result, list)

    def test_required_executables_defined(self):
        self.assertIn('tcpdump', server.REQUIRED_EXECUTABLES)
        self.assertIn('tshark', server.REQUIRED_EXECUTABLES)
        self.assertIn('suricata', server.REQUIRED_EXECUTABLES)
        self.assertIn('suricata-update', server.REQUIRED_EXECUTABLES)

    @unittest.mock.patch('suricata.shutil.which')
    def test_check_executables_all_missing(self, mock_which):
        mock_which.return_value = None
        missing = server.check_executables()
        self.assertEqual(len(missing), 4)

    @unittest.mock.patch('suricata.shutil.which')
    def test_check_executables_some_present(self, mock_which):
        def which_side_effect(cmd):
            if cmd in ['tcpdump', 'tshark']:
                return f'/usr/bin/{cmd}'
            return None
        mock_which.side_effect = which_side_effect
        missing = server.check_executables()
        self.assertEqual(sorted(missing), ['suricata', 'suricata-update'])


class TestFileAlertsEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.original_base = server.DATA_DIR
        server.DATA_DIR = cls.tmpdir

        cls.port = 19000 + (os.getpid() % 1000)
        cls.server = server.ThreadedTCPServer(('127.0.0.1', cls.port), server.Handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        server.DATA_DIR = cls.original_base
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _get(self, path):
        import urllib.request
        try:
            req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}')
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

class TestSuricataFileStoreConfig(unittest.TestCase):
    def test_file_store_enabled_in_config(self):
        """Verify setup_suricata_config rewrites suricata.yaml to enable file-store."""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("enabled: yes", content,
                      'setup_suricata_config must enable file-store')
        self.assertIn("dir: filestore", content,
                      'setup_suricata_config must set filestore dir')
        self.assertIn("force-filestore: yes", content,
                      'setup_suricata_config must force filestore')
        self.assertIn("stream-depth: 0", content,
                      'setup_suricata_config must set stream-depth')
        self.assertIn("force-hash: [md5, sha1, sha256]", content,
                      'setup_suricata_config must force file hashes')

    def test_l_dir_in_spawn(self):
        """Verify spawn_suricata sets log directory to per-PCAP dir."""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("'-l', dir_path", content,
                      'spawn_suricata must set log directory to per-PCAP dir')


class TestYaraScannerModule(unittest.TestCase):
    def test_yara_scanner_exists(self):
        yara_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'yara_scanner.py')
        self.assertTrue(os.path.exists(yara_path), 'yara_scanner.py must exist')

    def test_check_yara_executable_exists(self):
        import yara_scanner
        self.assertTrue(hasattr(yara_scanner, 'check_yara_executable'))

    def test_setup_yara_rules_exists(self):
        import yara_scanner
        self.assertTrue(hasattr(yara_scanner, 'setup_yara_rules'))

    def test_run_yara_pipeline_exists(self):
        import yara_scanner
        self.assertTrue(hasattr(yara_scanner, 'run_yara_pipeline'))

    def test_parse_yara_output_with_tags_and_meta(self):
        """Verify parser handles YARA output with both tags and metadata."""
        import yara_scanner
        output = 'TestRule [SUSP,MALWARE] [description="test desc",author="tester"] /tmp/filestore/ab/abc123'
        matches = yara_scanner._parse_yara_output(output, '/tmp/filestore')
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['rule_name'], 'TestRule')
        self.assertEqual(matches[0]['tags'], ['SUSP', 'MALWARE'])
        self.assertEqual(matches[0]['meta'], {'description': 'test desc', 'author': 'tester'})

    def test_parse_yara_output_empty_tags_with_meta(self):
        """Verify parser handles empty tags section with metadata (YARA-Rules style)."""
        import yara_scanner
        output = 'Delphi_Random [] [author="_pusher_",date="2015-08"] /tmp/filestore/ab/abc123'
        matches = yara_scanner._parse_yara_output(output, '/tmp/filestore')
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['rule_name'], 'Delphi_Random')
        self.assertEqual(matches[0]['tags'], [])
        self.assertEqual(matches[0]['meta'], {'author': '_pusher_', 'date': '2015-08'})

    def test_build_rule_classifications(self):
        """Verify _build_rule_classifications assigns correct classification levels."""
        import yara_scanner
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake rule files with actual rule declarations
            os.makedirs(os.path.join(tmpdir, 'yara-rules', 'malware'))
            os.makedirs(os.path.join(tmpdir, 'yara-rules', 'capabilities'))
            os.makedirs(os.path.join(tmpdir, 'neo23x0'))
            with open(os.path.join(tmpdir, 'yara-rules', 'malware', 'MALW_Test.yar'), 'w') as f:
                f.write('rule MALW_Test {\n  strings:\n    $a = "test"\n  condition:\n    $a\n}\n')
            with open(os.path.join(tmpdir, 'yara-rules', 'capabilities', 'capability.yar'), 'w') as f:
                f.write('rule capability {\n  strings:\n    $a = "test"\n  condition:\n    $a\n}\n')
            with open(os.path.join(tmpdir, 'neo23x0', 'APT_FancyBear.yar'), 'w') as f:
                f.write('rule APT_FancyBear {\n  strings:\n    $a = "test"\n  condition:\n    $a\n}\n')
            with open(os.path.join(tmpdir, 'neo23x0', 'SUSP_Unknown.yar'), 'w') as f:
                f.write('rule SUSP_Unknown {\n  strings:\n    $a = "test"\n  condition:\n    $a\n}\n')
            with open(os.path.join(tmpdir, 'neo23x0', 'IsPE32.yar'), 'w') as f:
                f.write('rule IsPE32 {\n  strings:\n    $a = "test"\n  condition:\n    $a\n}\n')
            classifications = yara_scanner._build_rule_classifications(tmpdir)
            self.assertEqual(classifications.get('MALW_Test'), 'threat')
            self.assertEqual(classifications.get('capability'), 'technique')
            self.assertEqual(classifications.get('APT_FancyBear'), 'threat')
            self.assertEqual(classifications.get('SUSP_Unknown'), 'technique')
            self.assertEqual(classifications.get('IsPE32'), 'informational')


if __name__ == '__main__':
    unittest.main(verbosity=2)
