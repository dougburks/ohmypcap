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
        source = inspect.getsource(db.create_sqlite_db)
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
