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
import sqlite3
import re

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import ohmypcap as server

SERVER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ohmypcap.py')


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

    def test_events_with_valid_md5(self):
        md5dir = os.path.join(self.tmpdir, 'd41d8cd98f00b204e9800998ecf8427e')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        server.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get('/api/events?md5=d41d8cd98f00b204e9800998ecf8427e')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data), 1)

    def test_events_requires_md5(self):
        status, body = self._get('/api/events')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

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

    def test_upload_non_pcap_content(self):
        status, body = self._post_multipart('/api/upload', 'fake.pcap', b'not a pcap file')
        self.assertEqual(status, 400)

    def test_upload_html_as_pcap(self):
        status, body = self._post_multipart('/api/upload', 'evil.pcap', b'<html><script>alert(1)</script></html>')
        self.assertEqual(status, 400)

    def test_upload_elf_as_pcap(self):
        status, body = self._post_multipart('/api/upload', 'malware.pcap', b'\x7fELF' + b'\x00' * 100)
        self.assertEqual(status, 400)

    def test_upload_wrong_extension(self):
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x00' * 100
        status, body = self._post_multipart('/api/upload', 'test.txt', pcap_data)
        self.assertEqual(status, 400)

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
        upload_section = content.split("if safe_filename.endswith('.zip'):")[1].split("pcap_files = [")[0]
        # Should try no password first
        self.assertIn("extracted = False", upload_section,
                      'Must track extraction success')
        self.assertIn("zip_ref.extractall(tmp_dir)", upload_section,
                      'Must attempt extraction without password')
        # Should try common passwords
        self.assertIn("passwords = [b'infected']", upload_section,
                      'Must try infected password')
        self.assertIn("for pwd in passwords:", upload_section,
                      'Must loop over candidate passwords')
        # Should try date-based password from filename
        self.assertIn("re.search(r'(\\d{4})-(\\d{2})-(\\d{2})', safe_filename)", upload_section,
                      'Must derive date-based password from filename')
        self.assertIn("'infected_{year}{month}{day}'.encode()", upload_section,
                      'Must construct MTA-style date password')

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
        self.assertIn('Invalid URL', data.get('error', ''))

    def test_load_url_rejects_localhost(self):
        status, body = self._post('/api/load-url', {'url': 'http://localhost/test.pcap'})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid URL', data.get('error', ''))

    def test_load_url_empty_url(self):
        status, body = self._post('/api/load-url', {'url': ''})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('No URL provided', data.get('error', ''))

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
    def test_load_url_validates_downloaded_content(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('validate_pcap_content(file_data)', content)
        self.assertIn('if not validate_pcap_content(file_data):', content)

    def test_load_url_double_validates_url(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # Count occurrences of validate_url_safety in the load-url handler
        load_url_section = content.split("elif self.path == '/api/load-url':")[1]
        load_url_section = load_url_section.split("elif self.path == '/api/check-status':")[0]
        self.assertEqual(load_url_section.count('validate_url_safety(url)'), 2,
                         'load-url should call validate_url_safety twice to prevent DNS rebinding')


class TestThreadedServer(unittest.TestCase):
    def test_threaded_server_class_exists(self):
        self.assertTrue(hasattr(server, 'ThreadedTCPServer'))


class TestSQLite(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.eve_file = os.path.join(self.tmpdir, 'eve.json')
        self.db_file = os.path.join(self.tmpdir, 'events.db')
        
        with open(self.eve_file, 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4", "src_port": 1234, "dest_ip": "5.6.7.8", "dest_port": 80, "proto": "TCP"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "1.2.3.4", "src_port": 1235, "dest_ip": "5.6.7.8", "dest_port": 53, "proto": "UDP"}\n')
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:02", "src_ip": "1.2.3.5", "src_port": 1236, "dest_ip": "5.6.7.9", "dest_port": 80, "proto": "TCP"}\n')
            f.write('{"event_type": "stats", "timestamp": "2026-01-01T00:00:03"}\n')
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir)
    
    def test_create_sqlite_db(self):
        server.create_sqlite_db(self.db_file, self.eve_file)
        self.assertTrue(os.path.exists(self.db_file))
    
    def test_query_events_sqlite_all(self):
        server.create_sqlite_db(self.db_file, self.eve_file)
        events = server.query_events_sqlite(self.db_file)
        self.assertEqual(len(events), 4)
    
    def test_query_events_sqlite_by_type(self):
        server.create_sqlite_db(self.db_file, self.eve_file)
        events = server.query_events_sqlite(self.db_file, event_type='alert')
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e['event_type'] == 'alert' for e in events))
    
    def test_query_events_sqlite_with_limit(self):
        server.create_sqlite_db(self.db_file, self.eve_file)
        events = server.query_events_sqlite(self.db_file, limit=2)
        self.assertEqual(len(events), 2)
    
    def test_query_events_sqlite_with_offset(self):
        server.create_sqlite_db(self.db_file, self.eve_file)
        events = server.query_events_sqlite(self.db_file, offset=2, limit=2)
        self.assertEqual(len(events), 2)
    
    def test_get_event_count_sqlite(self):
        server.create_sqlite_db(self.db_file, self.eve_file)
        count = server.get_event_count_sqlite(self.db_file)
        self.assertEqual(count, 4)
    
    def test_get_event_count_sqlite_by_type(self):
        server.create_sqlite_db(self.db_file, self.eve_file)
        count = server.get_event_count_sqlite(self.db_file, event_type='alert')
        self.assertEqual(count, 2)
    
    def test_get_event_types_sqlite(self):
        server.create_sqlite_db(self.db_file, self.eve_file)
        stats = server.get_event_types_sqlite(self.db_file)
        self.assertEqual(stats['alert'], 2)
        self.assertEqual(stats['dns'], 1)
        self.assertEqual(stats['stats'], 1)
    
    def test_sqlite_schema_has_indexes(self):
        server.create_sqlite_db(self.db_file, self.eve_file)
        conn = sqlite3.connect(self.db_file)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = [row[0] for row in cursor.fetchall()]
        conn.close()
        self.assertIn('idx_event_type', indexes)
        self.assertIn('idx_timestamp', indexes)


class TestSQLiteAPI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.eve_file = os.path.join(self.tmpdir, 'eve.json')
        self.db_file = os.path.join(self.tmpdir, 'events.db')
        
        with open(self.eve_file, 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "1.2.3.5"}\n')
        
        server.create_sqlite_db(self.db_file, self.eve_file)
        
        self.md5 = 'test12345678901234567890'
        os.makedirs(os.path.join(self.tmpdir, self.md5), exist_ok=True)
        shutil.copy(self.eve_file, os.path.join(self.tmpdir, self.md5, 'eve.json'))
        shutil.copy(self.db_file, os.path.join(self.tmpdir, self.md5, 'events.db'))
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir)
    
    def test_api_events_with_type_filter(self):
        events = server.query_events_sqlite(self.db_file, event_type='alert')
        self.assertTrue(all(e['event_type'] == 'alert' for e in events))
    
    def test_api_stats_endpoint_returns_types(self):
        stats = server.get_event_types_sqlite(self.db_file)
        self.assertIn('alert', stats)
        self.assertIn('dns', stats)


class TestSizeLimitMessages(unittest.TestCase):
    def test_max_eve_size_constant(self):
        self.assertEqual(server.MAX_EVE_SIZE, 1000 * 1024 * 1024)
    
    def test_error_message_consistency(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        error_count = content.count('max 1000MB')
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
        
        # Verify default-rule-path points to our custom directory
        expected_path = server.SURICATA_RULES_DIR
        self.assertIn(expected_path, content,
                      f'suricata.yaml should use custom rules path {expected_path}')
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


class TestSubprocessTimeouts(unittest.TestCase):
    def test_tcpdump_has_timeout(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        tcpdump_match = re.search(r"\['tcpdump', '-r', pcap, '-w', '-'.*?timeout=(\d+)", content, re.DOTALL)
        self.assertIsNotNone(tcpdump_match, 'tcpdump call must have timeout')
        self.assertEqual(tcpdump_match.group(1), '60')

    def test_tshark_has_timeout(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        tshark_matches = re.findall(r"\['tshark', '-r', pcap.*?timeout=(\d+)", content, re.DOTALL)
        self.assertGreaterEqual(len(tshark_matches), 2, 'Both tshark calls must have timeout')
        for m in tshark_matches:
            self.assertEqual(m, '60', 'tshark timeout must be 60 seconds')

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
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("print(f'Warning: could not copy", content)
        self.assertIn("print(f'Warning: could not copy directory", content)


class TestSuricataProcessingLock(unittest.TestCase):
    def test_processing_lock_file_used(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("'.processing'", content)
        self.assertIn("os.path.exists(processing_lock)", content)
        self.assertIn("open(processing_lock, 'w').close()", content)

    def test_lock_removed_in_callback(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("os.unlink(processing_lock)", content)

    def test_lock_removed_on_spawn_failure(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # Count occurrences of unlink inside except blocks
        # Should appear at least twice: once in callback, once in failure handler
        self.assertGreaterEqual(content.count("os.unlink(processing_lock)"), 2)

    def test_stale_lock_handled_in_check_status(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        check_status = content.split("elif self.path == '/api/check-status':")[1]
        self.assertIn("lock_age", check_status)
        self.assertIn("600", check_status)


class TestNameTxtPathSafety(unittest.TestCase):
    def test_analyses_checks_name_txt_safety(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        analyses_section = content.split("elif path == '/api/analyses':")[1].split("elif path == '/api/load-analysis':")[0]
        self.assertIn("is_safe_path(dir_path, name_path)", analyses_section,
                      '/api/analyses must validate name.txt path')

    def test_load_analysis_checks_name_txt_safety(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        load_section = content.split("elif path == '/api/load-analysis':")[1].split("elif path == '/api/delete-analysis':")[0]
        self.assertIn("is_safe_path(dir_path, name_path)", load_section,
                      '/api/load-analysis must validate name.txt path')


class TestSuricataRuleRawEnabled(unittest.TestCase):
    def test_rule_raw_set_in_suricata_spawn(self):
        """Verify that suricata is spawned with --set to enable alert.rule in eve.json"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # Should appear exactly once in spawn_suricata helper
        self.assertEqual(content.count("'--set', 'outputs.1.eve-log.types.0.alert.metadata.rule.raw=true'"), 1,
                         'rule.raw must be set exactly once in spawn_suricata helper')
        # Helper must be called from all 3 original spawn points plus reanalyze endpoint
        func_def_pos = content.find('def spawn_suricata(dir_path, pcap_path):')
        calls_after_def = content[func_def_pos:].count('spawn_suricata(dir_path, pcap_path)') - 1
        self.assertEqual(calls_after_def, 4,
                         'spawn_suricata must be called from all 3 upload paths and reanalyze endpoint')


class TestReanalyzeEndpoint(unittest.TestCase):
    def test_reanalyze_endpoint_exists(self):
        """Verify /api/reanalyze endpoint exists in do_POST."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("elif self.path == '/api/reanalyze':", content,
                      'POST /api/reanalyze endpoint must exist')

    def test_reanalyze_deletes_analysis_artifacts(self):
        """Verify reanalyze removes eve.json, events.db, and .processing."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("elif self.path == '/api/reanalyze':")[1]
        self.assertIn("for artifact in ('eve.json', 'events.db', '.processing'):", reanalyze_section,
                      'reanalyze must loop over analysis artifacts to delete')
        self.assertIn('os.unlink(artifact_path)', reanalyze_section,
                      'reanalyze must unlink artifact files')

    def test_reanalyze_keeps_pcap_and_name(self):
        """Verify reanalyze does NOT delete pcap files or name.txt."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("elif self.path == '/api/reanalyze':")[1]
        # Should only unlink artifacts, not rmtree the whole directory
        self.assertNotIn('shutil.rmtree', reanalyze_section,
                         'reanalyze must not use rmtree')
        # name.txt should not appear in an os.path.join inside the loop
        loop_section = reanalyze_section.split("for artifact in")[1].split("if spawn_suricata")[0]
        self.assertNotIn("name.txt", loop_section,
                         'reanalyze loop must not reference name.txt')

    def test_reanalyze_returns_404_if_no_pcap(self):
        """Verify reanalyze returns 404 when no PCAP is present."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("elif self.path == '/api/reanalyze':")[1]
        self.assertIn("self._send_error(404, 'No pcap found')", reanalyze_section,
                      'reanalyze must return 404 if no PCAP found')

    def test_reanalyze_returns_409_if_already_processing(self):
        """Verify reanalyze returns 409 when analysis is already in progress."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("elif self.path == '/api/reanalyze':")[1]
        self.assertIn("self._send_error(409, 'Analysis already in progress')", reanalyze_section,
                      'reanalyze must return 409 if already processing')

    def test_reanalyze_calls_spawn_suricata(self):
        """Verify reanalyze calls spawn_suricata after cleaning artifacts."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("elif self.path == '/api/reanalyze':")[1]
        self.assertIn('spawn_suricata(dir_path, pcap_path)', reanalyze_section,
                      'reanalyze must call spawn_suricata')


class TestRuleDownloadPrompt(unittest.TestCase):
    def test_rule_download_message_in_stdout(self):
        """Verify that suricata-update outputs messages when rules are downloaded"""
        with open(SERVER_FILE, 'r') as f:
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
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('def has_internet_access():', content,
                      'has_internet_access function must exist')

    def test_internet_check_connects_to_rules_server(self):
        """Verify internet check targets the actual rules server"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('rules.emergingthreats.net', content,
                      'Must check connectivity to rules server')
        self.assertIn('socket.create_connection', content,
                      'Must use socket.create_connection for check')

    def test_baked_in_rules_path_defined(self):
        """Verify baked-in rules path is referenced"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("/usr/share/suricata/rules", content,
                      'Must reference baked-in rules path')

    def test_fallback_uses_shutil_copytree(self):
        """Verify air-gapped fallback copies baked-in rules"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('shutil.copytree', content,
                      'Must use shutil.copytree for baked-in rules')
        self.assertIn('dirs_exist_ok=True', content,
                      'Must safely overwrite existing rules')

    def test_airgap_log_messages_present(self):
        """Verify log messages for air-gapped path exist"""
        with open(SERVER_FILE, 'r') as f:
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
        self.assertIn('Analyze pcap files from the web or your local collection', content)
        self.assertIn('View alerts and then slice and dice your network metadata', content)

    def test_running_message_has_border(self):
        """Verify the running message is wrapped in a border matching the welcome banner"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('OhMyPCAP running at http://', content)
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
        with open(html_file, 'r') as f:
            content = f.read()
        self.assertIn('id="loadingModal"', content, 'loadingModal element should exist')
        self.assertIn('.modal {', content, 'modal CSS should exist')
        self.assertIn('.modal.active {', content, 'modal.active CSS should exist')
        self.assertIn('.spinner {', content, 'spinner CSS should exist')
        self.assertIn('.spinner-dot {', content, 'spinner-dot CSS should exist')


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

    @unittest.mock.patch('ohmypcap.shutil.which')
    def test_check_executables_all_missing(self, mock_which):
        mock_which.return_value = None
        missing = server.check_executables()
        self.assertEqual(len(missing), 4)

    @unittest.mock.patch('ohmypcap.shutil.which')
    def test_check_executables_some_present(self, mock_which):
        def which_side_effect(cmd):
            if cmd in ['tcpdump', 'tshark']:
                return f'/usr/bin/{cmd}'
            return None
        mock_which.side_effect = which_side_effect
        missing = server.check_executables()
        self.assertEqual(sorted(missing), ['suricata', 'suricata-update'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
