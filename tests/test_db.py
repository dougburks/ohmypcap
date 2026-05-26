#!/usr/bin/env python3
import unittest
import os
import sys
import tempfile
import shutil
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import db

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'db.py')


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
        db.create_sqlite_db(self.db_file, self.eve_file)
        self.assertTrue(os.path.exists(self.db_file))
    
    def test_query_events_sqlite_all(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file)
        self.assertEqual(len(events), 4)
    
    def test_query_events_sqlite_by_type(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file, event_type='alert')
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e['event_type'] == 'alert' for e in events))
    
    def test_query_events_sqlite_with_limit(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file, limit=2)
        self.assertEqual(len(events), 2)
    
    def test_query_events_sqlite_with_offset(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file, offset=2, limit=2)
        self.assertEqual(len(events), 2)
    
    def test_get_event_count_sqlite(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        count = db.get_event_count_sqlite(self.db_file)
        self.assertEqual(count, 4)
    
    def test_get_event_count_sqlite_by_type(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        count = db.get_event_count_sqlite(self.db_file, event_type='alert')
        self.assertEqual(count, 2)
    
    def test_get_event_types_sqlite(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        stats = db.get_event_types_sqlite(self.db_file)
        self.assertEqual(stats['alert'], 2)
        self.assertEqual(stats['dns'], 1)
        self.assertEqual(stats['stats'], 1)
    
    def test_sqlite_schema_has_indexes(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        conn = sqlite3.connect(self.db_file)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = [row[0] for row in cursor.fetchall()]
        conn.close()
        self.assertIn('idx_event_type', indexes)
        self.assertIn('idx_timestamp', indexes)
        self.assertIn('idx_event_type_timestamp', indexes)

    def test_sqlite_sets_synchronous_normal(self):
        import inspect
        source = inspect.getsource(db._init_db)
        self.assertIn("PRAGMA synchronous = NORMAL", source)

    def test_sqlite_sets_busy_timeout(self):
        import inspect
        source = inspect.getsource(db._db_connection)
        self.assertIn("PRAGMA busy_timeout = 30000", source)

    def test_sqlite_runs_optimize_after_load(self):
        import inspect
        source = inspect.getsource(db.create_sqlite_db)
        self.assertIn("PRAGMA optimize", source)

    def test_sqlite_uses_wal_mode(self):
        import inspect
        source = inspect.getsource(db._init_db)
        self.assertIn("PRAGMA journal_mode = WAL", source)
        db.create_sqlite_db(self.db_file, self.eve_file)
        conn = sqlite3.connect(self.db_file)
        cursor = conn.execute("PRAGMA journal_mode")
        mode = cursor.fetchone()[0]
        conn.close()
        self.assertEqual(mode.lower(), 'wal')

    def test_sqlite_schema_has_fts5(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        conn = sqlite3.connect(self.db_file)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events_fts'")
        table = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(table)

    def test_query_events_sqlite_with_q(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file, q='dns')
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_type'], 'dns')

    def test_query_events_sqlite_with_q_and_type(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file, event_type='alert', q='1.2.3.4')
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_type'], 'alert')
        self.assertEqual(events[0]['src_ip'], '1.2.3.4')

    def test_get_event_count_sqlite_with_q(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        count = db.get_event_count_sqlite(self.db_file, q='alert')
        self.assertEqual(count, 2)

    def test_get_event_types_sqlite_with_q(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        stats = db.get_event_types_sqlite(self.db_file, q='TCP')
        self.assertEqual(stats.get('alert'), 2)
        self.assertNotIn('dns', stats)

    def test_query_events_sqlite_q_fallback_without_fts(self):
        conn = sqlite3.connect(self.db_file)
        conn.executescript(db.SQLITE_SCHEMA)
        conn.execute('''INSERT INTO events (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, json_data)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     ('alert', '2026-01-01T00:00:00', '1.2.3.4', 1234, '5.6.7.8', 80, 'TCP', '', '{"event_type":"alert"}'))
        conn.commit()
        conn.close()
        events = db.query_events_sqlite(self.db_file, q='alert')
        self.assertEqual(len(events), 1)

    def test_synthetic_filealerts_from_yara_matches(self):
        """YARA matches correlated with fileinfo create synthetic filealerts events."""
        import json as json_mod
        # Write a fileinfo event with a known SHA256
        with open(self.eve_file, 'a') as f:
            f.write(json_mod.dumps({
                'event_type': 'fileinfo',
                'timestamp': '2026-01-01T00:00:04',
                'src_ip': '192.168.1.1',
                'src_port': 12345,
                'dest_ip': '10.0.0.1',
                'dest_port': 80,
                'proto': 'TCP',
                'app_proto': 'http',
                'fileinfo': {
                    'sha256': 'a' * 64,
                    'filename': 'malware.exe',
                    'size': 1024,
                }
            }) + '\n')
        # Write a matching yara_matches.json
        yara_file = self.db_file.replace('events.db', 'yara_matches.json')
        with open(yara_file, 'w') as f:
            json_mod.dump([
                {
                    'rule_name': 'MALWARE_Test',
                    'sha256': 'a' * 64,
                    'tags': ['malware'],
                    'meta': {'author': 'test'},
                    'strings': [],
                    'file_id': 'file.1',
                }
            ], f)
        db.create_sqlite_db(self.db_file, self.eve_file)
        # Query filealerts events
        events = db.query_events_sqlite(self.db_file, event_type='filealerts')
        self.assertEqual(len(events), 1)
        fa = events[0]
        self.assertEqual(fa['event_type'], 'filealerts')
        self.assertEqual(fa['src_ip'], '192.168.1.1')
        self.assertEqual(fa['dest_ip'], '10.0.0.1')
        self.assertEqual(fa['src_port'], 12345)
        self.assertEqual(fa['dest_port'], 80)
        self.assertEqual(fa['proto'], 'TCP')
        self.assertEqual(fa['app_proto'], 'http')
        self.assertEqual(fa['filealerts']['rule_name'], 'MALWARE_Test')
        self.assertEqual(fa['filealerts']['sha256'], 'a' * 64)
        # Stats should include filealerts
        stats = db.get_event_types_sqlite(self.db_file)
        self.assertEqual(stats.get('filealerts'), 1)

    def test_yara_match_without_corresponding_fileinfo_is_ignored(self):
        """YARA matches with no matching fileinfo SHA256 are not inserted."""
        import json as json_mod
        yara_file = self.db_file.replace('events.db', 'yara_matches.json')
        with open(yara_file, 'w') as f:
            json_mod.dump([
                {
                    'rule_name': 'ORPHAN_Rule',
                    'sha256': 'z' * 64,
                    'confidence': 'technique',
                    'tags': [],
                    'meta': {},
                    'strings': [],
                }
            ], f)
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file, event_type='filealerts')
        self.assertEqual(len(events), 0)
        stats = db.get_event_types_sqlite(self.db_file)
        self.assertNotIn('filealerts', stats)

    def test_filealerts_searchable_via_fts5(self):
        """Synthetic filealerts events are indexed in FTS5 and searchable."""
        import json as json_mod
        with open(self.eve_file, 'a') as f:
            f.write(json_mod.dumps({
                'event_type': 'fileinfo',
                'timestamp': '2026-01-01T00:00:04',
                'src_ip': '192.168.1.1',
                'src_port': 12345,
                'dest_ip': '10.0.0.1',
                'dest_port': 80,
                'proto': 'TCP',
                'fileinfo': {'sha256': 'b' * 64}
            }) + '\n')
        yara_file = self.db_file.replace('events.db', 'yara_matches.json')
        with open(yara_file, 'w') as f:
            json_mod.dump([
                {
                    'rule_name': 'COBALTSTRIKE_Beacon',
                    'sha256': 'b' * 64,
                    'tags': ['apt', 'cobaltstrike'],
                    'meta': {},
                    'strings': [],
                }
            ], f)
        db.create_sqlite_db(self.db_file, self.eve_file)
        # Search by rule name
        events = db.query_events_sqlite(self.db_file, q='COBALTSTRIKE')
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_type'], 'filealerts')
        # Search by tag
        events = db.query_events_sqlite(self.db_file, q='cobaltstrike')
        self.assertEqual(len(events), 1)


    def test_create_file_analysis_db(self):
        """Standalone file analysis creates fileinfo + filealerts events."""
        import json as json_mod
        tmp_file = os.path.join(self.tmpdir, 'evil.exe')
        with open(tmp_file, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 62)
        db_file = os.path.join(self.tmpdir, 'file_events.db')
        yara_matches = [
            {
                'rule_name': 'MALWARE_Test',
                'tags': ['malware'],
                'meta': {'author': 'test'},
                'strings': [],
                'file_id': '',
            }
        ]
        db.create_file_analysis_db(
            db_file, tmp_file, yara_matches,
            file_md5='a' * 32, file_sha1='b' * 40, file_sha256='c' * 64,
            magic_desc='PE32 executable'
        )
        # Verify fileinfo event
        fileinfo_events = db.query_events_sqlite(db_file, event_type='fileinfo')
        self.assertEqual(len(fileinfo_events), 1)
        fi = fileinfo_events[0]
        self.assertEqual(fi['event_type'], 'fileinfo')
        self.assertEqual(fi['proto'], '')
        self.assertEqual(fi['fileinfo']['filename'], 'evil.exe')
        self.assertEqual(fi['fileinfo']['sha256'], 'c' * 64)
        self.assertEqual(fi['fileinfo']['magic'], 'PE32 executable')
        # Verify filealerts event
        alert_events = db.query_events_sqlite(db_file, event_type='filealerts')
        self.assertEqual(len(alert_events), 1)
        fa = alert_events[0]
        self.assertEqual(fa['event_type'], 'filealerts')
        self.assertEqual(fa['proto'], '')
        self.assertEqual(fa['filealerts']['rule_name'], 'MALWARE_Test')
        self.assertEqual(fa['filealerts']['sha256'], 'c' * 64)


class TestSQLiteAPI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.eve_file = os.path.join(self.tmpdir, 'eve.json')
        self.db_file = os.path.join(self.tmpdir, 'events.db')
        
        with open(self.eve_file, 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "1.2.3.5"}\n')
        
        db.create_sqlite_db(self.db_file, self.eve_file)
        
        self.md5 = 'test12345678901234567890'
        os.makedirs(os.path.join(self.tmpdir, self.md5), exist_ok=True)
        shutil.copy(self.eve_file, os.path.join(self.tmpdir, self.md5, 'eve.json'))
        shutil.copy(self.db_file, os.path.join(self.tmpdir, self.md5, 'events.db'))
    
    def tearDown(self):
        shutil.rmtree(self.tmpdir)
    
    def test_api_events_with_type_filter(self):
        events = db.query_events_sqlite(self.db_file, event_type='alert')
        self.assertTrue(all(e['event_type'] == 'alert' for e in events))
    
    def test_api_stats_endpoint_returns_types(self):
        stats = db.get_event_types_sqlite(self.db_file)
        self.assertIn('alert', stats)
        self.assertIn('dns', stats)

    def test_query_events_sqlite_multiple_q_like(self):
        """Multiple q terms must AND together (LIKE fallback)."""
        events = db.query_events_sqlite(self.db_file, q=['1.2.3.4', 'alert'])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_type'], 'alert')

    def test_get_event_count_sqlite_multiple_q(self):
        count = db.get_event_count_sqlite(self.db_file, q=['1.2.3.4', 'alert'])
        self.assertEqual(count, 1)

    def test_get_event_types_sqlite_multiple_q(self):
        stats = db.get_event_types_sqlite(self.db_file, q=['1.2.3.4', 'alert'])
        self.assertEqual(stats.get('alert'), 1)
        self.assertNotIn('dns', stats)

    def test_build_search_terms_from_string(self):
        self.assertEqual(db._build_search_terms('foo'), ['foo'])

    def test_build_search_terms_from_list(self):
        self.assertEqual(db._build_search_terms(['foo', 'bar']), ['foo', 'bar'])

    def test_build_search_terms_empty(self):
        self.assertEqual(db._build_search_terms(None), [])
        self.assertEqual(db._build_search_terms(''), [])
        self.assertEqual(db._build_search_terms([]), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
