#!/usr/bin/env python3
import json
import unittest
import unittest.mock
import os
import sys
import tempfile
import shutil
import sqlite3
import subprocess

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

    def test_create_sqlite_db_skips_non_dict_json_lines(self):
        """REGRESSION: a line can be syntactically valid JSON (a bare
        number/string/array) without being an event object - plausible
        with a truncated/corrupted eve.json. The ingest loop's try/except
        only caught json.JSONDecodeError; event.get(...) on a non-dict
        raised AttributeError instead, which wasn't caught, aborting
        ingestion of the whole file instead of just skipping the one bad
        line (which is what the same try/except already does for a
        malformed line)."""
        eve_file = os.path.join(self.tmpdir, 'eve_non_dict_lines.json')
        with open(eve_file, 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4", "src_port": 1234, "dest_ip": "5.6.7.8", "dest_port": 80, "proto": "TCP"}\n')
            f.write('42\n')  # bare number - valid JSON, not an object
            f.write('"just a string"\n')  # bare string
            f.write('[1, 2, 3]\n')  # bare array
            f.write('null\n')  # bare null
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "1.2.3.4", "src_port": 1235, "dest_ip": "5.6.7.8", "dest_port": 53, "proto": "UDP"}\n')

        db.create_sqlite_db(self.db_file, eve_file)  # must not raise
        events = db.query_events_sqlite(self.db_file)
        self.assertEqual(len(events), 2, 'both real events must still be ingested, non-dict lines just skipped')
        self.assertEqual({e['event_type'] for e in events}, {'alert', 'dns'})

    def test_query_events_sqlite_all(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file)
        # The merged/all-types query excludes the internal 'stats' summary
        # row (3 real events + 1 stats row in the fixture).
        self.assertEqual(len(events), 3)
        self.assertTrue(all(e['event_type'] != 'stats' for e in events))
    
    def test_query_events_sqlite_by_type(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file, event_type='alert')
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e['event_type'] == 'alert' for e in events))
    
    def test_create_sqlite_db_reclassifies_protocol_command_decode_alerts(self):
        """Suricata's own built-in protocol-command-decode rules (opt-in via
        show_protocol_decode_alerts) are noise, not real detections - see
        docs/architecture/event-types.md's note on protocol_decode. Only an
        alert whose category is exactly "Generic Protocol Command Decode"
        gets reclassified; an ordinary alert with a different category must
        be left as 'alert' (proves this discriminates, not "everything
        becomes protocol_decode")."""
        eve_file = self._write_eve('eve_protocol_decode.json', [
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'SURICATA STREAM bad TCP', 'category': 'Generic Protocol Command Decode', 'severity': 3}},
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'ET MALWARE Sig', 'category': 'Trojan', 'severity': 2}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        events = db.query_events_sqlite(self.db_file)
        by_sig = {e['alert']['signature']: e for e in events}
        self.assertEqual(by_sig['SURICATA STREAM bad TCP']['event_type'], 'protocol_decode')
        self.assertEqual(by_sig['ET MALWARE Sig']['event_type'], 'alert')
        # The stored json_data blob's own event_type field must match the
        # indexed column too, not just the column (in case they ever drift).
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT event_type, json_data FROM events WHERE json_extract(json_data, '$.alert.signature') = ?",
                ('SURICATA STREAM bad TCP',)
            ).fetchone()
            self.assertEqual(row['event_type'], 'protocol_decode')
            self.assertEqual(json.loads(row['json_data'])['event_type'], 'protocol_decode')

    def test_query_events_sqlite_with_limit(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file, limit=2)
        self.assertEqual(len(events), 2)
    
    def test_query_events_sqlite_with_offset(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file, offset=2, limit=2)
        # Only 3 non-stats events exist, so offset=2 leaves just 1 remaining.
        self.assertEqual(len(events), 1)

    def test_sort_expr_time_maps_to_timestamp(self):
        self.assertEqual(db._sort_expr('flow', 'Time'), 'timestamp')
        self.assertEqual(db._sort_expr('flow', 'Time', prefix='e.'), 'e.timestamp')

    def test_sort_expr_real_column(self):
        self.assertEqual(db._sort_expr('flow', 'Protocol'), 'protocol')
        self.assertEqual(db._sort_expr('flow', 'Source IP', prefix='e.'), 'e.src_ip')

    def test_sort_expr_port_columns_sort_numerically_not_as_text(self):
        """REGRESSION: REAL_AGGREGATION_COLUMNS marks Source/Dest Port
        cast_text=True so the aggregation table's GROUP BY output is
        uniformly a string - but src_port/dest_port are real INTEGER
        columns, and _sort_expr (used for the events table's ORDER BY, not
        aggregation) must not reuse that flag: casting to TEXT for sorting
        would order port 3306 before 443 before 80, surprising an analyst
        who clicks the Source Port/Dest Port column header expecting
        numeric order."""
        self.assertEqual(db._sort_expr('flow', 'Source Port'), 'src_port')
        self.assertEqual(db._sort_expr('flow', 'Dest Port', prefix='e.'), 'e.dest_port')

    def test_sort_expr_json_path_column(self):
        expr = db._sort_expr('flow', 'Pkts →')
        self.assertIn("json_extract(json_data, '$.flow.pkts_toserver')", expr)

    def test_sort_expr_unrecognized_label_returns_none(self):
        self.assertIsNone(db._sort_expr('flow', 'Not A Real Column'))
        # A column that's valid for a different event type isn't valid here.
        self.assertIsNone(db._sort_expr('flow', 'Query'))

    def test_sort_expr_unrecognized_event_type_returns_none(self):
        self.assertIsNone(db._sort_expr('not_a_type', 'Pkts →'))

    def test_sort_expr_merged_type_column(self):
        expr = db._sort_expr(None, 'Type')
        self.assertEqual(expr, 'UPPER(event_type)')
        self.assertEqual(db._sort_expr(None, 'Type', prefix='e.'), 'UPPER(e.event_type)')

    def test_sort_expr_merged_detail_column(self):
        expr = db._sort_expr(None, 'Detail')
        self.assertIn("CASE event_type", expr)
        self.assertIn("WHEN 'alert' THEN", expr)
        self.assertIn("WHEN 'flow' THEN", expr)

    def test_sort_expr_merged_only_columns_return_none_for_specific_type(self):
        """'Type'/'Detail' are only merged-view columns - a per-type tab
        (which never has them in getColumnsForType) must never resolve them
        to anything, real or bogus."""
        self.assertIsNone(db._sort_expr('flow', 'Detail'))

    def test_sort_expr_dns_dnp3_type_not_shadowed_by_merged_case(self):
        """REGRESSION: adding a merged-view 'Type' special case to _sort_expr
        must not shadow dns/dnp3's own real, JSON-path-backed 'Type' column -
        both already existed before the merged-view support was added, and
        must keep taking precedence for their own per-type queries."""
        self.assertEqual(db._sort_expr('dns', 'Type'),
                         "COALESCE(json_extract(json_data, '$.dns.rrtype'), json_extract(json_data, '$.dns.queries[0].rrtype'))")
        self.assertEqual(db._sort_expr('dnp3', 'Type'), "json_extract(json_data, '$.dnp3.type')")

    def test_query_events_sqlite_order_by_real_column_asc_desc(self):
        eve_file = self._write_eve('eve_sort_real.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'proto': 'TCP', 'src_ip': '1.1.1.1'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'proto': 'UDP', 'src_ip': '2.2.2.2'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:02', 'proto': 'ICMP', 'src_ip': '3.3.3.3'},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        asc = db.query_events_sqlite(self.db_file, event_type='flow', order_by='Protocol', sort_dir='asc')
        self.assertEqual([e['proto'] for e in asc], ['ICMP', 'TCP', 'UDP'])
        desc = db.query_events_sqlite(self.db_file, event_type='flow', order_by='Protocol', sort_dir='desc')
        self.assertEqual([e['proto'] for e in desc], ['UDP', 'TCP', 'ICMP'])

    def test_query_events_sqlite_order_by_json_column(self):
        eve_file = self._write_eve('eve_sort_json.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'flow': {'pkts_toserver': 30}},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '2.2.2.2',
             'flow': {'pkts_toserver': 10}},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:02', 'src_ip': '3.3.3.3',
             'flow': {'pkts_toserver': 20}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        events = db.query_events_sqlite(self.db_file, event_type='flow', order_by='Pkts →', sort_dir='asc')
        self.assertEqual([e['flow']['pkts_toserver'] for e in events], [10, 20, 30])

    def test_query_events_sqlite_unrecognized_order_by_falls_back_to_timestamp(self):
        eve_file = self._write_eve('eve_sort_fallback.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:02', 'src_ip': '3.3.3.3'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '2.2.2.2'},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        events = db.query_events_sqlite(self.db_file, event_type='flow', order_by='Not A Real Column')
        self.assertEqual([e['src_ip'] for e in events], ['1.1.1.1', '2.2.2.2', '3.3.3.3'])

    def test_query_events_sqlite_order_by_ties_use_timestamp_tiebreaker(self):
        """Sorting by a column with many ties (e.g. Protocol, only 2 distinct
        values) must not produce an unstable/nondeterministic order across
        pages - the implicit timestamp secondary sort keeps it deterministic."""
        eve_file = self._write_eve('eve_sort_tiebreak.json', [
            {'event_type': 'flow', 'timestamp': f'2026-01-01T00:00:{i:02d}', 'proto': 'TCP', 'src_ip': f'1.1.1.{i}'}
            for i in range(10)
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        page1 = db.query_events_sqlite(self.db_file, event_type='flow', offset=0, limit=5, order_by='Protocol')
        page2 = db.query_events_sqlite(self.db_file, event_type='flow', offset=5, limit=5, order_by='Protocol')
        all_ips = [e['src_ip'] for e in page1] + [e['src_ip'] for e in page2]
        # All 10 rows appear exactly once across the two pages - no duplicates, none skipped.
        self.assertEqual(sorted(all_ips), sorted(f'1.1.1.{i}' for i in range(10)))
        self.assertEqual(len(set(all_ips)), 10)

    def test_query_events_sqlite_order_by_with_search_terms_fts_prefix(self):
        """order_by must still resolve correctly when combined with active
        search terms, which switch the query to the FTS-joined form using
        an 'e.' table alias prefix."""
        eve_file = self._write_eve('eve_sort_fts.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'proto': 'UDP', 'src_ip': '1.1.1.1'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'proto': 'TCP', 'src_ip': '1.1.1.2'},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        events = db.query_events_sqlite(self.db_file, event_type='flow', q='1.1.1', order_by='Protocol', sort_dir='asc')
        self.assertEqual([e['proto'] for e in events], ['TCP', 'UDP'])

    def test_query_events_sqlite_merged_order_by_type(self):
        eve_file = self._write_eve('eve_merged_type.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1'},
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:01', 'alert': {'signature': 'sig1'}},
            {'event_type': 'dns', 'timestamp': '2026-01-01T00:00:02', 'dns': {'rrname': 'example.com'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        events = db.query_events_sqlite(self.db_file, event_type=None, order_by='Type', sort_dir='asc')
        self.assertEqual([e['event_type'] for e in events], ['alert', 'dns', 'flow'])

    def test_query_events_sqlite_merged_order_by_detail_across_mixed_types(self):
        """Sorting the merged 'all' view by Detail must work across several
        different event types simultaneously - including the flow port-0
        elision case (must sort/display as '' not '0', so its Detail starts
        with '1.1.1.1: ...' not '1.1.1.1:0 ...') and a tls row with no sni
        (must be '' with no '-' default, unlike the aggregation column)."""
        eve_file = self._write_eve('eve_merged_detail.json', [
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00', 'alert': {'signature': 'zzz last'}},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '1.1.1.1', 'src_port': 0, 'dest_ip': '2.2.2.2', 'dest_port': 443},
            {'event_type': 'tls', 'timestamp': '2026-01-01T00:00:02', 'tls': {}},
            {'event_type': 'dns', 'timestamp': '2026-01-01T00:00:03', 'dns': {'rrname': 'aaa.example.com'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        events = db.query_events_sqlite(self.db_file, event_type=None, order_by='Detail', sort_dir='asc')
        # Ascending text order: '' (tls) < '1.1.1.1: → 2.2.2.2:443' (flow,
        # port-0 elided so it starts with a digit) < 'aaa...' (dns) < 'zzz...' (alert).
        self.assertEqual([e['event_type'] for e in events], ['tls', 'flow', 'dns', 'alert'])

    def _assert_json_matches_dict_query(self, **kwargs):
        """query_events_sqlite_json's parsed output must contain the same
        events (content-equivalent, not necessarily byte-identical - key
        order/whitespace may differ) as query_events_sqlite's dict list."""
        expected = db.query_events_sqlite(self.db_file, **kwargs)
        json_str, ids = db.query_events_sqlite_json(self.db_file, **kwargs)
        actual = json.loads(json_str)
        self.assertEqual(actual, expected)
        self.assertEqual(ids, [e['id'] for e in expected])
        return actual

    def test_query_events_sqlite_json_no_filter(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        self._assert_json_matches_dict_query()

    def test_query_events_sqlite_json_by_type(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        result = self._assert_json_matches_dict_query(event_type='alert')
        self.assertEqual(len(result), 2)

    def test_query_events_sqlite_json_with_limit_and_offset(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        self._assert_json_matches_dict_query(limit=1, offset=1)

    def test_query_events_sqlite_json_with_q(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        self._assert_json_matches_dict_query(q='dns')

    def test_query_events_sqlite_json_with_q_fts_prefix(self):
        eve_file = self._write_eve('eve_json_fts.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'proto': 'UDP', 'src_ip': '1.1.1.1'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'proto': 'TCP', 'src_ip': '1.1.1.2'},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        self._assert_json_matches_dict_query(event_type='flow', q='1.1.1', order_by='Protocol', sort_dir='asc')

    def test_query_events_sqlite_json_order_by_real_column(self):
        eve_file = self._write_eve('eve_json_sort.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'proto': 'TCP', 'src_ip': '1.1.1.1'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'proto': 'UDP', 'src_ip': '2.2.2.2'},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        result = self._assert_json_matches_dict_query(event_type='flow', order_by='Protocol', sort_dir='desc')
        self.assertEqual([e['proto'] for e in result], ['UDP', 'TCP'])

    def test_query_events_sqlite_json_empty_result(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        result = self._assert_json_matches_dict_query(event_type='nonexistent_type')
        self.assertEqual(result, [])

    def test_query_events_sqlite_json_no_events_table(self):
        db.init_empty_db(self.db_file)
        self.assertEqual(db.query_events_sqlite_json(self.db_file), ('[]', []))

    def test_query_events_sqlite_json_is_valid_parseable_json(self):
        """The raw-passthrough output must be directly usable as an HTTP
        response body - i.e. round-trip through json.loads without error,
        even though it's built from string concatenation, not json.dumps."""
        db.create_sqlite_db(self.db_file, self.eve_file)
        json_str, ids = db.query_events_sqlite_json(self.db_file)
        parsed = json.loads(json_str)
        self.assertIsInstance(parsed, list)
        self.assertTrue(all(isinstance(e, dict) for e in parsed))
        self.assertEqual(len(ids), len(parsed))

    def test_query_events_sqlite_json_malformed_row_becomes_empty_object(self):
        """A corrupted json_data blob must not break the entire response -
        query_events_sqlite_json's cheap shape check (not a full parse)
        replaces it with just its id, matching query_events_sqlite's own
        graceful-degradation behavior for the same scenario (an empty dict,
        now also carrying 'id' like every other row - see id-exposure
        comment on query_events_sqlite_json)."""
        conn = sqlite3.connect(self.db_file)
        conn.executescript(db.SQLITE_SCHEMA)
        conn.execute('''INSERT INTO events (event_type, timestamp, json_data)
                        VALUES (?, ?, ?)''', ('alert', '2026-01-01T00:00:00', '{"valid": true}'))
        conn.execute('''INSERT INTO events (event_type, timestamp, json_data)
                        VALUES (?, ?, ?)''', ('dns', '2026-01-01T00:00:01', 'not valid json'))
        conn.execute('''INSERT INTO events (event_type, timestamp, json_data)
                        VALUES (?, ?, ?)''', ('http', '2026-01-01T00:00:02', '{"valid": true}'))
        conn.commit()
        conn.close()

        json_str, ids = db.query_events_sqlite_json(self.db_file)
        events = json.loads(json_str)
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0], {'valid': True, 'id': ids[0]})
        self.assertEqual(events[1], {'id': ids[1]})
        self.assertEqual(events[2], {'valid': True, 'id': ids[2]})

    def test_get_row_notes_empty_row_ids_returns_empty_dict(self):
        self.assertEqual(db.get_row_notes(self.db_file, 'events', []), {})

    def test_get_row_notes_no_row_notes_table_returns_empty_dict(self):
        """A db.py file created before this table existed must degrade
        gracefully, not raise - same convention as _has_events_table
        checks elsewhere in this file."""
        conn = sqlite3.connect(self.db_file)
        conn.execute('CREATE TABLE events (id INTEGER PRIMARY KEY)')
        conn.commit()
        conn.close()
        self.assertEqual(db.get_row_notes(self.db_file, 'events', [1, 2, 3]), {})

    def test_set_row_note_then_get_row_notes_round_trip(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        event_id = db.query_events_sqlite(self.db_file)[0]['id']
        db.set_row_note(self.db_file, 'events', event_id, 'a note')
        self.assertEqual(db.get_row_notes(self.db_file, 'events', [event_id]), {event_id: 'a note'})

    def test_set_row_note_overwrites(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        event_id = db.query_events_sqlite(self.db_file)[0]['id']
        db.set_row_note(self.db_file, 'events', event_id, 'first')
        db.set_row_note(self.db_file, 'events', event_id, 'second')
        self.assertEqual(db.get_row_notes(self.db_file, 'events', [event_id]), {event_id: 'second'})

    def test_set_row_note_empty_deletes_row(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        event_id = db.query_events_sqlite(self.db_file)[0]['id']
        db.set_row_note(self.db_file, 'events', event_id, 'will be cleared')
        db.set_row_note(self.db_file, 'events', event_id, '')
        self.assertEqual(db.get_row_notes(self.db_file, 'events', [event_id]), {})

    def test_get_row_notes_only_returns_requested_ids(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file)
        id_a, id_b = events[0]['id'], events[1]['id']
        db.set_row_note(self.db_file, 'events', id_a, 'note a')
        db.set_row_note(self.db_file, 'events', id_b, 'note b')
        self.assertEqual(db.get_row_notes(self.db_file, 'events', [id_a]), {id_a: 'note a'})

    def test_row_notes_discriminate_by_source_table(self):
        """The same numeric id in events vs sigma_alerts must be
        independent notes - proves UNIQUE(source_table, row_id) and the
        WHERE clause both actually discriminate."""
        db.create_sqlite_db(self.db_file, self.eve_file)
        db.insert_sigma_alerts(self.db_file, [{
            'timestamp': '2026-01-01T00:00:00', 'rule_title': 'r', 'rule_id': 'r1',
            'severity': 'high', 'level': 'high',
        }])
        event_id = db.query_events_sqlite(self.db_file)[0]['id']
        sigma_id = db.query_sigma_alerts_sqlite(self.db_file)[0]['id']
        db.set_row_note(self.db_file, 'events', event_id, 'events note')
        self.assertEqual(db.get_row_notes(self.db_file, 'sigma_alerts', [sigma_id]), {})
        self.assertEqual(db.get_row_notes(self.db_file, 'events', [event_id]), {event_id: 'events note'})

    def test_row_notes_do_not_survive_events_db_rebuild(self):
        """REGRESSION (intentional, not a bug): /api/reanalyze deletes
        events.db entirely (os.unlink, both PCAP_ANALYSIS_ARTIFACTS and
        FILE_ANALYSIS_ARTIFACTS include it) before rebuilding it from
        scratch with fresh autoincrement ids from 1. Since row_notes lives
        inside that same file, it's destroyed along with everything else -
        proven here directly at the file level, matching what reanalyze
        actually does, without needing a full HTTP-level reanalyze."""
        db.create_sqlite_db(self.db_file, self.eve_file)
        event_id = db.query_events_sqlite(self.db_file)[0]['id']
        db.set_row_note(self.db_file, 'events', event_id, 'will not survive')
        self.assertEqual(db.get_row_notes(self.db_file, 'events', [event_id]), {event_id: 'will not survive'})

        os.unlink(self.db_file)
        db.create_sqlite_db(self.db_file, self.eve_file)

        new_event_id = db.query_events_sqlite(self.db_file)[0]['id']
        self.assertEqual(new_event_id, event_id, 'autoincrement restarts at 1 - same id, different row')
        self.assertEqual(db.get_row_notes(self.db_file, 'events', [new_event_id]), {},
                         'row_notes must not survive a rebuilt events.db, even at the same numeric id')

    def test_has_row_notes_false_when_db_file_missing(self):
        self.assertFalse(db.has_row_notes(self.db_file))

    def test_has_row_notes_false_when_no_row_notes_table(self):
        conn = sqlite3.connect(self.db_file)
        conn.execute('CREATE TABLE events (id INTEGER PRIMARY KEY)')
        conn.commit()
        conn.close()
        self.assertFalse(db.has_row_notes(self.db_file))

    def test_has_row_notes_false_when_no_notes_set(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        self.assertFalse(db.has_row_notes(self.db_file))

    def test_has_row_notes_true_after_setting_one_note(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        event_id = db.query_events_sqlite(self.db_file)[0]['id']
        db.set_row_note(self.db_file, 'events', event_id, 'a note')
        self.assertTrue(db.has_row_notes(self.db_file))

    def test_has_row_notes_true_for_a_sigma_alert_note(self):
        """Not scoped to 'events' only - a note on any source_table counts."""
        db.create_sqlite_db(self.db_file, self.eve_file)
        db.insert_sigma_alerts(self.db_file, [{
            'timestamp': '2026-01-01T00:00:00', 'rule_title': 'r', 'rule_id': 'r1',
            'severity': 'high', 'level': 'high',
        }])
        sigma_id = db.query_sigma_alerts_sqlite(self.db_file)[0]['id']
        db.set_row_note(self.db_file, 'sigma_alerts', sigma_id, 'a sigma note')
        self.assertTrue(db.has_row_notes(self.db_file))

    def test_has_row_notes_false_again_after_clearing_the_only_note(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        event_id = db.query_events_sqlite(self.db_file)[0]['id']
        db.set_row_note(self.db_file, 'events', event_id, 'temporary')
        db.set_row_note(self.db_file, 'events', event_id, '')
        self.assertFalse(db.has_row_notes(self.db_file))

    def test_set_acknowledged_true_then_events_query_excludes_it(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        alert_id = db.query_events_sqlite(self.db_file, event_type='alert')[0]['id']
        db.set_acknowledged(self.db_file, 'events', alert_id, True)
        remaining_ids = [e['id'] for e in db.query_events_sqlite(self.db_file, event_type='alert')]
        self.assertNotIn(alert_id, remaining_ids)

    def test_set_acknowledged_false_reincludes_it(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        alert_id = db.query_events_sqlite(self.db_file, event_type='alert')[0]['id']
        db.set_acknowledged(self.db_file, 'events', alert_id, True)
        db.set_acknowledged(self.db_file, 'events', alert_id, False)
        remaining_ids = [e['id'] for e in db.query_events_sqlite(self.db_file, event_type='alert')]
        self.assertIn(alert_id, remaining_ids)

    def test_acknowledging_one_row_does_not_affect_unrelated_rows(self):
        """REGRESSION: the acknowledged-exclusion subquery originally used
        a bare `id` column inside its correlated EXISTS/NOT EXISTS clause,
        which SQL resolved to acknowledged_alerts.id (the innermost table
        in scope) instead of the outer events.id - as soon as any row was
        acknowledged, every row (including unrelated dns rows) vanished
        from every query. Fixed by fully qualifying to events.id/e.id."""
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file)
        alert_ids = [e['id'] for e in events if e['event_type'] == 'alert']
        dns_ids = [e['id'] for e in events if e['event_type'] == 'dns']
        db.set_acknowledged(self.db_file, 'events', alert_ids[0], True)
        remaining_ids = {e['id'] for e in db.query_events_sqlite(self.db_file)}
        self.assertNotIn(alert_ids[0], remaining_ids)
        self.assertIn(alert_ids[1], remaining_ids)
        self.assertIn(dns_ids[0], remaining_ids)

    def test_get_event_count_sqlite_drops_after_acknowledge(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        alert_id = db.query_events_sqlite(self.db_file, event_type='alert')[0]['id']
        self.assertEqual(db.get_event_count_sqlite(self.db_file), 3)
        db.set_acknowledged(self.db_file, 'events', alert_id, True)
        self.assertEqual(db.get_event_count_sqlite(self.db_file), 2)

    def test_query_events_sqlite_acknowledged_only_returns_just_that_row(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        alert_id = db.query_events_sqlite(self.db_file, event_type='alert')[0]['id']
        db.set_acknowledged(self.db_file, 'events', alert_id, True)
        only_ids = [e['id'] for e in db.query_events_sqlite(self.db_file, acknowledged_only=True)]
        self.assertEqual(only_ids, [alert_id])

    def test_get_event_count_sqlite_acknowledged_only(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        alert_id = db.query_events_sqlite(self.db_file, event_type='alert')[0]['id']
        db.set_acknowledged(self.db_file, 'events', alert_id, True)
        self.assertEqual(db.get_event_count_sqlite(self.db_file, acknowledged_only=True), 1)

    def test_set_acknowledged_bulk_acknowledges_every_id(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        alert_ids = [e['id'] for e in db.query_events_sqlite(self.db_file, event_type='alert')]
        db.set_acknowledged_bulk(self.db_file, 'events', alert_ids)
        remaining = db.query_events_sqlite(self.db_file, event_type='alert')
        self.assertEqual(remaining, [])

    def test_set_acknowledged_bulk_empty_list_is_a_no_op(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        db.set_acknowledged_bulk(self.db_file, 'events', [])
        self.assertEqual(db.get_event_count_sqlite(self.db_file), 3)

    def test_acknowledged_alerts_discriminate_by_source_table(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        db.insert_sigma_alerts(self.db_file, [{
            'timestamp': '2026-01-01T00:00:00', 'rule_title': 'r', 'rule_id': 'r1',
            'severity': 'high', 'level': 'high',
        }])
        event_id = db.query_events_sqlite(self.db_file, event_type='alert')[0]['id']
        sigma_id = db.query_sigma_alerts_sqlite(self.db_file)[0]['id']
        db.set_acknowledged(self.db_file, 'events', event_id, True)
        sigma_remaining = db.query_sigma_alerts_sqlite(self.db_file)
        self.assertEqual([a['id'] for a in sigma_remaining], [sigma_id])

    def test_sigma_alert_acknowledged_excludes_from_default_query(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        db.insert_sigma_alerts(self.db_file, [{
            'timestamp': '2026-01-01T00:00:00', 'rule_title': 'r', 'rule_id': 'r1',
            'severity': 'high', 'level': 'high',
        }])
        sigma_id = db.query_sigma_alerts_sqlite(self.db_file)[0]['id']
        db.set_acknowledged(self.db_file, 'sigma_alerts', sigma_id, True)
        self.assertEqual(db.query_sigma_alerts_sqlite(self.db_file), [])
        self.assertEqual(db.get_sigma_alert_count_sqlite(self.db_file), 0)
        only = db.query_sigma_alerts_sqlite(self.db_file, acknowledged_only=True)
        self.assertEqual([a['id'] for a in only], [sigma_id])
        self.assertEqual(db.get_sigma_alert_count_sqlite(self.db_file, acknowledged_only=True), 1)

    def test_get_event_count_sqlite(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        count = db.get_event_count_sqlite(self.db_file)
        # Excludes the internal 'stats' summary row.
        self.assertEqual(count, 3)
    
    def test_get_event_count_sqlite_by_type(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        count = db.get_event_count_sqlite(self.db_file, event_type='alert')
        self.assertEqual(count, 2)
    
    def test_get_event_types_sqlite(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        stats = db.get_event_types_sqlite(self.db_file)
        self.assertEqual(stats['alert'], 2)
        self.assertEqual(stats['dns'], 1)
        # 'stats' is an internal summary row, excluded from the merged/all-
        # types query (event_type=None) just like query_events_sqlite.
        self.assertNotIn('stats', stats)
    
    def test_get_event_date_range_sqlite(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        date_range = db.get_event_date_range_sqlite(self.db_file)
        # Fixture's non-stats events span 00:00:00 to 00:00:02; the stats
        # row at 00:00:03 must be excluded from the range (it would otherwise
        # be the max).
        self.assertEqual(date_range['min'], '2026-01-01T00:00:00')
        self.assertEqual(date_range['max'], '2026-01-01T00:00:02')

    def test_get_event_date_range_sqlite_with_q(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        date_range = db.get_event_date_range_sqlite(self.db_file, q='dns')
        self.assertEqual(date_range['min'], '2026-01-01T00:00:01')
        self.assertEqual(date_range['max'], '2026-01-01T00:00:01')

    def test_get_event_date_range_sqlite_no_events(self):
        db.init_empty_db(self.db_file)
        date_range = db.get_event_date_range_sqlite(self.db_file)
        self.assertIsNone(date_range['min'])
        self.assertIsNone(date_range['max'])

    def test_get_sankey_data_sqlite_basic_shape_and_values(self):
        # Fixture (setUp): alert 1.2.3.4->5.6.7.8:80, dns 1.2.3.4->5.6.7.8:53,
        # alert 1.2.3.5->5.6.7.9:80, plus one 'stats' row (must be excluded).
        db.create_sqlite_db(self.db_file, self.eve_file)
        data = db.get_sankey_data_sqlite(self.db_file)

        node_names_by_col = {0: set(), 1: set(), 2: set()}
        for n in data['nodes']:
            node_names_by_col[n['column']].add(n['name'])
        self.assertEqual(node_names_by_col[0], {'1.2.3.4', '1.2.3.5'})
        self.assertEqual(node_names_by_col[1], {'5.6.7.8', '5.6.7.9'})
        self.assertEqual(node_names_by_col[2], {'80', '53'})

        def link_value(source_name, target_name):
            for l in data['links']:
                if l['source'].endswith(':' + source_name) and l['target'].endswith(':' + target_name):
                    return l['value']
            return None

        self.assertEqual(link_value('1.2.3.4', '5.6.7.8'), 2)
        self.assertEqual(link_value('1.2.3.5', '5.6.7.9'), 1)
        self.assertEqual(link_value('5.6.7.8', '80'), 1)
        self.assertEqual(link_value('5.6.7.8', '53'), 1)
        self.assertEqual(link_value('5.6.7.9', '80'), 1)

    def test_get_sankey_data_sqlite_excludes_stats_row(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        data = db.get_sankey_data_sqlite(self.db_file)
        total_events = sum(l['value'] for l in data['links'] if l['source'].startswith('0:'))
        self.assertEqual(total_events, 3, "the 'stats' row's src/dest must not be counted")

    def test_get_sankey_data_sqlite_with_event_type_filter(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        data = db.get_sankey_data_sqlite(self.db_file, event_type='dns')
        names = {n['name'] for n in data['nodes']}
        self.assertIn('1.2.3.4', names)
        self.assertNotIn('1.2.3.5', names, 'alert-only src_ip must be excluded by the dns type filter')

    def test_get_sankey_data_sqlite_with_q(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        data = db.get_sankey_data_sqlite(self.db_file, q='dns')
        names = {n['name'] for n in data['nodes']}
        self.assertIn('1.2.3.4', names)
        self.assertNotIn('1.2.3.5', names)

    def test_get_sankey_data_sqlite_does_not_crash_after_acknowledging_an_alert(self):
        """REGRESSION: get_sankey_data_sqlite's 5 node/link queries build
        their WHERE clause (including the acknowledged-exclusion check)
        inside a ThreadPoolExecutor worker (see run()). Checking whether
        acknowledged_alerts exists via conn.execute() from inside that
        worker - instead of once on the main thread beforehand - would
        raise sqlite3.ProgrammingError ("SQLite objects created in a
        thread can only be used in that same thread"), since conn is the
        connection this function's own with-block created on the main
        thread. Only exercised once something has actually been
        acknowledged (the exclusion clause is unconditional either way,
        but this proves the threaded path itself doesn't blow up)."""
        db.create_sqlite_db(self.db_file, self.eve_file)
        alert_id = db.query_events_sqlite(self.db_file, event_type='alert')[0]['id']
        db.set_acknowledged(self.db_file, 'events', alert_id, True)
        data = db.get_sankey_data_sqlite(self.db_file)
        self.assertIn('nodes', data)
        self.assertIn('links', data)

    def test_get_sankey_data_sqlite_no_events(self):
        db.init_empty_db(self.db_file)
        data = db.get_sankey_data_sqlite(self.db_file)
        self.assertEqual(data, {'nodes': [], 'links': []})

    def test_get_sankey_data_sqlite_dest_port_zero_normalizes_to_question_mark(self):
        eve_file = os.path.join(self.tmpdir, 'eve_port0.json')
        with open(eve_file, 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2"}\n')
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_sankey_data_sqlite(self.db_file)
        port_names = {n['name'] for n in data['nodes'] if n['column'] == 2}
        self.assertEqual(port_names, {'?'})

    def test_get_sankey_data_sqlite_other_bucketing(self):
        eve_file = os.path.join(self.tmpdir, 'eve_many_ips.json')
        with open(eve_file, 'w') as f:
            # 60 distinct src_ips with distinct, descending event counts so
            # ranking is deterministic: ip i has (60-i) events.
            for i in range(60):
                for _ in range(60 - i):
                    f.write(json.dumps({
                        'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00',
                        'src_ip': f'10.0.0.{i}', 'dest_ip': '9.9.9.9', 'dest_port': 80,
                    }) + '\n')
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_sankey_data_sqlite(self.db_file, max_nodes_per_column=50)

        col0_nodes = [n for n in data['nodes'] if n['column'] == 0]
        self.assertEqual(len(col0_nodes), 51, '50 kept + 1 Other node')
        self.assertTrue(any(n['name'] == 'Other' for n in col0_nodes))

        other_value = sum(l['value'] for l in data['links'] if l['source'].endswith(':Other') and l['source'].startswith('0:'))
        dropped_total = sum(60 - i for i in range(50, 60))  # ips 50..59 dropped
        self.assertEqual(other_value, dropped_total)

    def test_get_sankey_data_sqlite_exact_boundary_produces_no_other_node(self):
        eve_file = os.path.join(self.tmpdir, 'eve_exactly_50.json')
        with open(eve_file, 'w') as f:
            for i in range(50):
                f.write(json.dumps({
                    'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00',
                    'src_ip': f'10.0.0.{i}', 'dest_ip': '9.9.9.9', 'dest_port': 80,
                }) + '\n')
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_sankey_data_sqlite(self.db_file, max_nodes_per_column=50)
        col0_nodes = [n for n in data['nodes'] if n['column'] == 0]
        self.assertEqual(len(col0_nodes), 50)
        self.assertFalse(any(n['name'] == 'Other' for n in col0_nodes))

    def test_get_sankey_data_sqlite_correct_under_concurrency_at_scale(self):
        """get_sankey_data_sqlite runs its 5 node/link GROUP BY queries on
        separate threads/connections for speed - verify counts are computed
        correctly (no cross-thread interference) with enough rows that the
        queries actually overlap in wall-clock time."""
        eve_file = os.path.join(self.tmpdir, 'eve_sankey_scale.json')
        with open(eve_file, 'w') as f:
            for i in range(2000):
                f.write(json.dumps({
                    'event_type': 'alert', 'timestamp': f'2026-01-01T00:00:{i % 60:02d}',
                    'src_ip': '1.1.1.1' if i % 2 == 0 else '3.3.3.3',
                    'dest_ip': '2.2.2.2', 'dest_port': 80 if i % 3 == 0 else 443,
                }) + '\n')
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_sankey_data_sqlite(self.db_file)

        def link_value(source_name, target_name):
            for l in data['links']:
                if l['source'].endswith(':' + source_name) and l['target'].endswith(':' + target_name):
                    return l['value']
            return None

        self.assertEqual(link_value('1.1.1.1', '2.2.2.2'), 1000)
        self.assertEqual(link_value('3.3.3.3', '2.2.2.2'), 1000)
        port80_count = sum(1 for i in range(2000) if i % 3 == 0)
        self.assertEqual(link_value('2.2.2.2', '80'), port80_count)
        self.assertEqual(link_value('2.2.2.2', '443'), 2000 - port80_count)

    def test_get_sankey_data_sqlite_one_query_failure_does_not_affect_others(self):
        """If one of the 5 node/link queries raises sqlite3.OperationalError
        (e.g. a malformed expression), the others - computed on independent
        threads/connections - must still return correctly, and the broken
        query must degrade to an empty result rather than crashing."""
        eve_file = os.path.join(self.tmpdir, 'eve_sankey_resilience.json')
        with open(eve_file, 'w') as f:
            f.write(json.dumps({
                'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00',
                'src_ip': '1.1.1.1', 'dest_ip': '2.2.2.2', 'dest_port': 80,
            }) + '\n')
        db.create_sqlite_db(self.db_file, eve_file)

        real_events_select = db._events_select
        def broken_events_select(terms, has_fts, select_cols_plain, select_cols_fts):
            # Uniquely identifies the dest_ip->dest_port link query (link1):
            # only it selects both a dest_port-derived column and 'AS dst'.
            if 'dest_port' in select_cols_plain and 'AS dst' in select_cols_plain:
                return 'SELECT this is not valid sql(', None
            return real_events_select(terms, has_fts, select_cols_plain, select_cols_fts)

        with unittest.mock.patch.object(db, '_events_select', side_effect=broken_events_select):
            data = db.get_sankey_data_sqlite(self.db_file)

        # Src IP -> Dest IP link (unaffected) must still be correct.
        def link_value(source_name, target_name):
            for l in data['links']:
                if l['source'].endswith(':' + source_name) and l['target'].endswith(':' + target_name):
                    return l['value']
            return None
        self.assertEqual(link_value('1.1.1.1', '2.2.2.2'), 1)
        # Dest IP -> Dest Port link (broken) contributes no links, but must
        # not have crashed the whole function or corrupted the other results.
        self.assertIsNone(link_value('2.2.2.2', '80'))
        names_by_col = {0: set(), 1: set(), 2: set()}
        for n in data['nodes']:
            names_by_col[n['column']].add(n['name'])
        self.assertEqual(names_by_col[0], {'1.1.1.1'})
        self.assertEqual(names_by_col[1], {'2.2.2.2'})
        self.assertEqual(names_by_col[2], {'80'})

    def test_create_sqlite_db_has_ip_port_indexes(self):
        """New analyses get the src_ip/dest_ip/dest_port/src_port indexes
        (SQLITE_SCHEMA) that get_sankey_data_sqlite/get_aggregation_data_sqlite
        rely on for fast GROUP BY - for free at ingest time."""
        db.create_sqlite_db(self.db_file, self.eve_file)
        conn = sqlite3.connect(self.db_file)
        index_names = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()}
        conn.close()
        for expected in ('idx_src_dest_ip', 'idx_dest_ip_port', 'idx_dest_port', 'idx_src_port'):
            self.assertIn(expected, index_names)

    def test_get_sankey_data_sqlite_backfills_missing_indexes(self):
        """Databases created before these indexes existed (e.g. an
        already-uploaded analysis from before this fix shipped) must still
        work correctly, and get the indexes backfilled transparently on
        first use - not just silently keep doing full table scans forever."""
        db.create_sqlite_db(self.db_file, self.eve_file)
        conn = sqlite3.connect(self.db_file)
        for idx in ('idx_src_dest_ip', 'idx_dest_ip_port', 'idx_dest_port', 'idx_src_port'):
            conn.execute(f'DROP INDEX {idx}')
        conn.commit()
        conn.close()

        data = db.get_sankey_data_sqlite(self.db_file)
        node_names_by_col = {0: set(), 1: set(), 2: set()}
        for n in data['nodes']:
            node_names_by_col[n['column']].add(n['name'])
        self.assertEqual(node_names_by_col[0], {'1.2.3.4', '1.2.3.5'})

        conn = sqlite3.connect(self.db_file)
        index_names = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()}
        conn.close()
        for expected in ('idx_src_dest_ip', 'idx_dest_ip_port', 'idx_dest_port', 'idx_src_port'):
            self.assertIn(expected, index_names)

    def test_get_aggregation_data_sqlite_backfills_missing_indexes(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        conn = sqlite3.connect(self.db_file)
        for idx in ('idx_src_dest_ip', 'idx_dest_ip_port', 'idx_dest_port', 'idx_src_port'):
            conn.execute(f'DROP INDEX {idx}')
        conn.commit()
        conn.close()

        data = db.get_aggregation_data_sqlite(self.db_file, 'alert')
        self.assertTrue(data)

    def test_ensure_ip_port_indexes_refreshes_planner_stats(self):
        """REGRESSION: backfilling these indexes onto a pre-existing database
        without refreshing sqlite_stat1 left the query planner working from
        stale/missing stats - with several indexes now sharing event_type as
        a leading column, it could pick an unhelpful one even for unrelated
        queries (measured: a plain 'sort by time' query regressed 17x on a
        1M-row backfilled database). PRAGMA optimize at the end of the
        backfill must keep sqlite_stat1 current."""
        db.create_sqlite_db(self.db_file, self.eve_file)
        conn = sqlite3.connect(self.db_file)
        for idx in ('idx_src_dest_ip', 'idx_dest_ip_port', 'idx_dest_port', 'idx_src_port'):
            conn.execute(f'DROP INDEX {idx}')
        conn.execute('DELETE FROM sqlite_stat1')
        conn.commit()
        conn.close()

        db.get_sankey_data_sqlite(self.db_file)

        conn = sqlite3.connect(self.db_file)
        stat_count = conn.execute("SELECT COUNT(*) FROM sqlite_stat1").fetchone()[0]
        conn.close()
        self.assertGreater(stat_count, 0, 'PRAGMA optimize must repopulate sqlite_stat1 after backfilling indexes')

    def test_create_sqlite_db_has_flow_json_indexes(self):
        """New analyses get flow's 6 JSON-extracted aggregation column
        indexes (Pkts/Bytes/State/Alerted) built in bulk after ingest, the
        standout bottleneck measured at 1M+ rows (~2s/column unindexed)."""
        db.create_sqlite_db(self.db_file, self.eve_file)
        conn = sqlite3.connect(self.db_file)
        index_names = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()}
        conn.close()
        for expected in ('idx_flow_pkts_toserver', 'idx_flow_pkts_toclient',
                         'idx_flow_bytes_toserver', 'idx_flow_bytes_toclient',
                         'idx_flow_state', 'idx_flow_alerted'):
            self.assertIn(expected, index_names)

    def test_get_aggregation_data_sqlite_backfills_flow_json_indexes(self):
        """Pre-existing databases (created before this fix shipped) must
        still return correct flow aggregation results, and get the JSON
        column indexes backfilled transparently on first use."""
        eve_file = self._write_eve('eve_flow_backfill.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'flow': {'pkts_toserver': 5, 'state': 'closed', 'alerted': True}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        conn = sqlite3.connect(self.db_file)
        for idx in ('idx_flow_pkts_toserver', 'idx_flow_pkts_toclient',
                    'idx_flow_bytes_toserver', 'idx_flow_bytes_toclient',
                    'idx_flow_state', 'idx_flow_alerted'):
            conn.execute(f'DROP INDEX {idx}')
        conn.commit()
        conn.close()

        data = db.get_aggregation_data_sqlite(self.db_file, 'flow')
        self.assertEqual(data['Pkts →'], [{'value': '5', 'count': 1}])
        self.assertEqual(data['State'], [{'value': 'closed', 'count': 1}])
        self.assertEqual(data['Alerted'], [{'value': 'Yes', 'count': 1}])

        conn = sqlite3.connect(self.db_file)
        index_names = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()}
        conn.close()
        for expected in ('idx_flow_pkts_toserver', 'idx_flow_pkts_toclient',
                         'idx_flow_bytes_toserver', 'idx_flow_bytes_toclient',
                         'idx_flow_state', 'idx_flow_alerted'):
            self.assertIn(expected, index_names)

    def test_ensure_flow_json_indexes_refreshes_planner_stats(self):
        eve_file = self._write_eve('eve_flow_stats_refresh.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP', 'flow': {'pkts_toserver': 5}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        conn = sqlite3.connect(self.db_file)
        for idx in ('idx_flow_pkts_toserver', 'idx_flow_pkts_toclient',
                    'idx_flow_bytes_toserver', 'idx_flow_bytes_toclient',
                    'idx_flow_state', 'idx_flow_alerted'):
            conn.execute(f'DROP INDEX {idx}')
        conn.execute('DELETE FROM sqlite_stat1')
        conn.commit()
        conn.close()

        db.get_aggregation_data_sqlite(self.db_file, 'flow')

        conn = sqlite3.connect(self.db_file)
        stat_count = conn.execute("SELECT COUNT(*) FROM sqlite_stat1").fetchone()[0]
        conn.close()
        self.assertGreater(stat_count, 0, 'PRAGMA optimize must repopulate sqlite_stat1 after backfilling flow JSON indexes')

    def test_aggregation_cast_text_includes_flow_state_and_alerted(self):
        self.assertIn(('flow', 'State'), db.AGGREGATION_CAST_TEXT)
        self.assertIn(('flow', 'Alerted'), db.AGGREGATION_CAST_TEXT)

    def test_get_aggregation_data_sqlite_flow_alerted_missing_key_is_no(self):
        """Regression: adding ('flow', 'Alerted') to AGGREGATION_CAST_TEXT
        (needed so its expression index is trusted as covering) must not
        change displayed values - a missing 'alerted' key (json_extract
        returns NULL) must still show 'No', matching the pre-existing
        True/False behavior already covered elsewhere."""
        eve_file = self._write_eve('eve_flow_no_alerted_key.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP', 'flow': {}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'flow')
        self.assertEqual(data['Alerted'], [{'value': 'No', 'count': 1}])

        conn = sqlite3.connect(self.db_file)
        index_names = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()}
        conn.close()
        for expected in ('idx_src_dest_ip', 'idx_dest_ip_port', 'idx_dest_port', 'idx_src_port'):
            self.assertIn(expected, index_names)

    def _write_eve(self, filename, event_dicts):
        eve_file = os.path.join(self.tmpdir, filename)
        with open(eve_file, 'w') as f:
            for e in event_dicts:
                f.write(json.dumps(e) + '\n')
        return eve_file

    def test_get_aggregation_data_sqlite_no_events(self):
        db.init_empty_db(self.db_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'alert')
        self.assertEqual(data, {})

    def test_get_aggregation_data_sqlite_unsupported_event_type(self):
        db.create_sqlite_db(self.db_file, self.eve_file)
        # 'log'/'sigmaalert' aren't in AGGREGATION_JSON_PATHS - the frontend's
        # canUseServerAggregation() never requests them, but the backend must
        # degrade gracefully (empty dict) rather than error. event_type=None
        # ('all', the merged view) is now explicitly supported - see
        # test_get_aggregation_data_sqlite_merged_all_events below.
        self.assertEqual(db.get_aggregation_data_sqlite(self.db_file, 'log'), {})

    def test_get_aggregation_data_sqlite_alert(self):
        eve_file = self._write_eve('eve_alert.json', [
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'Sig A', 'category': 'Trojan', 'severity': 2}},
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'Sig A', 'category': 'Trojan', 'severity': 2}},
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:02', 'src_ip': '3.3.3.3',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'Sig B', 'category': 'Info', 'severity': 0}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'alert')
        self.assertEqual(data['Alert'], [{'value': 'Sig A', 'count': 2}, {'value': 'Sig B', 'count': 1}])
        self.assertEqual(data['Category'], [{'value': 'Trojan', 'count': 2}, {'value': 'Info', 'count': 1}])
        # Severity: 'Sev ' + value formatting, including a genuine severity=0.
        self.assertIn({'value': 'Sev 2', 'count': 2}, data['Severity'])
        self.assertIn({'value': 'Sev 0', 'count': 1}, data['Severity'])
        self.assertEqual(data['Protocol'], [{'value': 'TCP', 'count': 3}])

    def test_get_aggregation_data_sqlite_does_not_crash_after_acknowledging_an_alert(self):
        """Same threading regression as
        test_get_sankey_data_sqlite_does_not_crash_after_acknowledging_an_alert,
        for get_aggregation_data_sqlite's run_column() worker closure."""
        eve_file = self._write_eve('eve_agg_ack.json', [
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'Sig A', 'category': 'Trojan', 'severity': 2}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        alert_id = db.query_events_sqlite(self.db_file, event_type='alert')[0]['id']
        db.set_acknowledged(self.db_file, 'events', alert_id, True)
        data = db.get_aggregation_data_sqlite(self.db_file, 'alert')
        self.assertEqual(data, {}, 'the only alert is acknowledged - every aggregation column must come back empty')

    def test_get_aggregation_data_sqlite_alert_ruleset(self):
        """'Ruleset' buckets alerts by signature_id via
        suricata_sid_ranges.SURICATA_SID_RANGES (see
        AGGREGATION_VALUE_TRANSFORMS[('alert', 'Ruleset')]) - two alerts
        from et/open's SID range and one from oisf/trafficid's must group
        into two distinct buckets, not get lumped together or misattributed
        (this exact misattribution - trafficid getting swallowed by
        urlhaus's then-unbounded range - was a real bug caught while
        building this feature)."""
        eve_file = self._write_eve('eve_alert_ruleset.json', [
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'ET Sig', 'category': 'Trojan', 'severity': 2, 'signature_id': 2010957}},
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'ET Sig 2', 'category': 'Trojan', 'severity': 2, 'signature_id': 2013000}},
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:02', 'src_ip': '3.3.3.3',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'Traffic ID Sig', 'category': 'Info', 'severity': 0, 'signature_id': 300000010}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'alert')
        self.assertEqual(sorted(data['Ruleset'], key=lambda r: -r['count']), [
            {'value': 'Emerging Threats Open', 'count': 2},
            {'value': 'Suricata Traffic ID', 'count': 1},
        ])

    def test_sort_expr_supports_alert_ruleset(self):
        self.assertIsNotNone(db._sort_expr('alert', 'Ruleset'))

    def test_get_aggregation_data_sqlite_protocol_decode(self):
        """protocol_decode's AGGREGATION_JSON_PATHS entry mirrors 'alert''s
        verbatim - same underlying JSON shape, since reclassification only
        rewrites event_type (see test_create_sqlite_db_reclassifies_
        protocol_command_decode_alerts)."""
        eve_file = self._write_eve('eve_protocol_decode_agg.json', [
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'SURICATA STREAM bad TCP', 'category': 'Generic Protocol Command Decode', 'severity': 3}},
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 80, 'proto': 'TCP',
             'alert': {'signature': 'SURICATA STREAM bad TCP', 'category': 'Generic Protocol Command Decode', 'severity': 3}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'protocol_decode')
        self.assertEqual(data['Alert'], [{'value': 'SURICATA STREAM bad TCP', 'count': 2}])
        self.assertEqual(data['Category'], [{'value': 'Generic Protocol Command Decode', 'count': 2}])
        self.assertIn({'value': 'Sev 3', 'count': 2}, data['Severity'])

    def test_all_events_detail_expr_protocol_decode(self):
        """The merged 'All Events' view's Detail column must also show
        protocol_decode's alert.signature, mirroring 'alert' (see
        test_get_aggregation_data_sqlite_merged_all_events for the pattern
        this extends)."""
        eve_file = self._write_eve('eve_protocol_decode_detail.json', [
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00', 'proto': 'TCP',
             'alert': {'signature': 'SURICATA STREAM bad TCP', 'category': 'Generic Protocol Command Decode', 'severity': 3}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, None)
        detail_values = {e['value'] for e in data['Detail']}
        self.assertIn('SURICATA STREAM bad TCP', detail_values)
        type_counts = {e['value']: e['count'] for e in data['Type']}
        self.assertEqual(type_counts, {'PROTOCOL_DECODE': 1})

    def test_get_aggregation_data_sqlite_dns(self):
        eve_file = self._write_eve('eve_dns.json', [
            {'event_type': 'dns', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'UDP', 'dns': {'rrname': 'example.com', 'rrtype': 'A'}},
            {'event_type': 'dns', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'UDP', 'dns': {'rrname': 'example.com', 'rrtype': 'A'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'dns')
        self.assertEqual(data['Query'], [{'value': 'example.com', 'count': 2}])
        self.assertEqual(data['Type'], [{'value': 'A', 'count': 2}])

    def test_get_aggregation_data_sqlite_dns_v3_format(self):
        """REGRESSION: Suricata 8's new V3 DNS logging format (the new
        default - confirmed against rust/src/dns/log.rs and real Suricata
        8.0.6 output) removed the flat dns.rrname/dns.rrtype fields entirely,
        moving the same info to dns.queries[0].rrname/rrtype instead. Every
        DNS row's Query/Type silently aggregated to nothing but '(empty)'
        under Suricata 8 before this fix - a severe regression given DNS is
        one of the highest-volume, most-viewed event types."""
        eve_file = self._write_eve('eve_dns_v3.json', [
            {'event_type': 'dns', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'UDP',
             'dns': {'version': 3, 'type': 'request',
                     'queries': [{'rrname': 'example.com', 'rrtype': 'A'}]}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'dns')
        self.assertEqual(data['Query'], [{'value': 'example.com', 'count': 1}])
        self.assertEqual(data['Type'], [{'value': 'A', 'count': 1}])

    def test_get_aggregation_data_sqlite_http(self):
        eve_file = self._write_eve('eve_http.json', [
            {'event_type': 'http', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'http': {'http_method': 'GET', 'hostname': 'example.com', 'url': '/a', 'status': 200,
                      'http_user_agent': 'X' * 60}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'http')
        self.assertEqual(data['Method'], [{'value': 'GET', 'count': 1}])
        self.assertEqual(data['Host'], [{'value': 'example.com', 'count': 1}])
        self.assertEqual(data['Status'], [{'value': '200', 'count': 1}])
        # User-Agent truncated to CONFIG.USER_AGENT_MAX_LENGTH=50, matching extractValue's .slice(0, 50).
        self.assertEqual(data['User-Agent'], [{'value': 'X' * 50, 'count': 1}])

    def test_get_aggregation_data_sqlite_http2_traffic_aggregates_under_http(self):
        """REGRESSION: Suricata always logs HTTP/2 (including cleartext h2c)
        under event_type 'http', reusing the plain HTTP field names
        (http_method/url/status) - confirmed against rust/src/http2/logger.rs
        and a real h2c capture. There is no event_type 'http2' in real data,
        so AGGREGATION_JSON_PATHS must have no 'http2' entry, and this
        'http'-keyed data (note: no 'hostname', since Suricata's http2 logger
        only maps a literal "host" header to it, not ":authority") must
        still aggregate correctly via the existing 'http' entry."""
        eve_file = self._write_eve('eve_http2.json', [
            {'event_type': 'http', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'http': {'version': '2', 'http_method': 'GET', 'url': '/robots.txt', 'status': 200,
                      'http_user_agent': 'curl/7.61.0', 'http2': {'stream_id': 1}}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        self.assertNotIn('http2', db.AGGREGATION_JSON_PATHS)
        data = db.get_aggregation_data_sqlite(self.db_file, 'http')
        self.assertEqual(data['Method'], [{'value': 'GET', 'count': 1}])
        self.assertEqual(data['URL'], [{'value': '/robots.txt', 'count': 1}])
        self.assertEqual(data['Status'], [{'value': '200', 'count': 1}])

    def test_get_aggregation_data_sqlite_tls_defaults_and_truncation(self):
        eve_file = self._write_eve('eve_tls.json', [
            {'event_type': 'tls', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'tls': {'sni': 'a.com', 'version': 'TLS 1.2', 'subject': 'CN=' + 'a' * 60, 'issuerdn': 'CN=' + 'b' * 60}},
            {'event_type': 'tls', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '3.3.3.3',
             'dest_ip': '2.2.2.2', 'proto': 'TCP', 'tls': {}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'tls')
        # Missing TLS fields default to the literal '-', not '(empty)', matching extractValue exactly.
        self.assertIn({'value': '-', 'count': 1}, data['SNI / Host'])
        self.assertIn({'value': 'a.com', 'count': 1}, data['SNI / Host'])
        # Subject/Issuer truncated to CONFIG.TLS_SUBJECT_MAX_LENGTH=40.
        self.assertTrue(any(e['value'] == ('CN=' + 'a' * 60)[:40] for e in data['Subject']))
        self.assertTrue(any(e['value'] == ('CN=' + 'b' * 60)[:40] for e in data['Issuer']))

    def test_get_aggregation_data_sqlite_flow_defaults_and_boolean(self):
        eve_file = self._write_eve('eve_flow.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'flow': {'pkts_toserver': 5, 'bytes_toserver': 100, 'state': 'closed', 'alerted': True}},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '3.3.3.3',
             'dest_ip': '2.2.2.2', 'proto': 'TCP', 'flow': {'alerted': False}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'flow')
        # Missing Pkts/Bytes default to 0 (as text), not '(empty)'.
        self.assertIn({'value': '5', 'count': 1}, data['Pkts →'])
        self.assertIn({'value': '0', 'count': 1}, data['Pkts →'])
        self.assertEqual(sorted(e['value'] for e in data['Alerted']), ['No', 'Yes'])

    def test_get_aggregation_data_sqlite_fileinfo_and_filealerts_tags_array(self):
        eve_file = self._write_eve('eve_fileinfo.json', [
            {'event_type': 'fileinfo', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP', 'fileinfo': {'filename': 'a.exe'}},
            {'event_type': 'filealerts', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '',
             'dest_ip': '', 'dest_port': 0, 'proto': '',
             'filealerts': {'rule_name': 'RULE_A', 'tags': []}},
            {'event_type': 'filealerts', 'timestamp': '2026-01-01T00:00:02', 'src_ip': '',
             'dest_ip': '', 'dest_port': 0, 'proto': '',
             'filealerts': {'rule_name': 'RULE_B', 'tags': ['MALWARE', 'SUSPICIOUS']}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        fileinfo_data = db.get_aggregation_data_sqlite(self.db_file, 'fileinfo')
        self.assertEqual(fileinfo_data['Filename'], [{'value': 'a.exe', 'count': 1}])

        filealerts_data = db.get_aggregation_data_sqlite(self.db_file, 'filealerts')
        self.assertIn({'value': 'RULE_A', 'count': 1}, filealerts_data['Rule Name'])
        self.assertIn({'value': '(empty)', 'count': 1}, filealerts_data['Tags'])
        self.assertIn({'value': 'MALWARE, SUSPICIOUS', 'count': 1}, filealerts_data['Tags'])

    def test_get_aggregation_data_sqlite_preserves_column_order_under_concurrency(self):
        """get_aggregation_data_sqlite runs each column's GROUP BY query on its
        own thread/connection for speed - the returned dict's key order must
        still match REAL_AGGREGATION_COLUMNS followed by AGGREGATION_JSON_PATHS,
        regardless of which thread happens to finish first."""
        eve_file = self._write_eve('eve_flow_order.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'flow': {'pkts_toserver': 5, 'bytes_toserver': 100, 'state': 'closed', 'alerted': True}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'flow')
        expected_order = list(db.REAL_AGGREGATION_COLUMNS.keys()) + list(db.AGGREGATION_JSON_PATHS['flow'].keys())
        # Only columns with at least one non-empty entry are included, but
        # relative order among present keys must still match the expected order.
        self.assertEqual(list(data.keys()), [k for k in expected_order if k in data])

    def test_get_aggregation_data_sqlite_correct_under_concurrency_at_scale(self):
        """Each column's query runs on a separate thread/connection - verify
        counts are computed correctly (no cross-thread interference) with
        enough rows that the queries actually overlap in wall-clock time."""
        events = []
        for i in range(2000):
            events.append({
                'event_type': 'flow', 'timestamp': f'2026-01-01T00:00:{i % 60:02d}',
                'src_ip': '1.1.1.1', 'dest_ip': '2.2.2.2', 'proto': 'TCP' if i % 2 == 0 else 'UDP',
                'flow': {'pkts_toserver': i % 10, 'state': 'closed' if i % 3 == 0 else 'established'},
            })
        eve_file = self._write_eve('eve_flow_scale.json', events)
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'flow')

        protocol_counts = {e['value']: e['count'] for e in data['Protocol']}
        self.assertEqual(protocol_counts['TCP'], 1000)
        self.assertEqual(protocol_counts['UDP'], 1000)

        state_counts = {e['value']: e['count'] for e in data['State']}
        closed_count = sum(1 for i in range(2000) if i % 3 == 0)
        self.assertEqual(state_counts['closed'], closed_count)
        self.assertEqual(state_counts['established'], 2000 - closed_count)

    def test_get_aggregation_data_sqlite_one_column_failure_does_not_affect_others(self):
        """If one column's query raises sqlite3.OperationalError (e.g. a
        malformed expression), the others - computed on independent
        threads/connections - must still return correctly."""
        eve_file = self._write_eve('eve_flow_resilience.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP', 'flow': {'pkts_toserver': 5}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)

        real_expr = db._aggregation_expr
        def broken_expr(event_type, label, paths, prefix=''):
            if label == 'State':
                return 'this is not valid sql('
            return real_expr(event_type, label, paths, prefix=prefix)

        with unittest.mock.patch.object(db, '_aggregation_expr', side_effect=broken_expr):
            data = db.get_aggregation_data_sqlite(self.db_file, 'flow')

        self.assertNotIn('State', data)
        self.assertEqual(data['Protocol'], [{'value': 'TCP', 'count': 1}])
        self.assertEqual(data['Pkts →'], [{'value': '5', 'count': 1}])

    def test_get_aggregation_data_sqlite_modbus_category_bugfix(self):
        # REGRESSION: modbus's 'Category' column previously always rendered
        # empty client-side (extractValue's Category case had no modbus
        # branch and fell through to e.alert?.category, always undefined
        # for modbus events) - this must return the real value.
        eve_file = self._write_eve('eve_modbus.json', [
            {'event_type': 'modbus', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 502, 'proto': 'TCP',
             'modbus': {'request': {'function_code': 'WrMultCoils', 'unit_id': 1,
                                     'access_type': 'WRITE', 'category': 'PUBLIC_ASSIGNED',
                                     'error_flags': 'NONE'}}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'modbus')
        self.assertEqual(data['Category'], [{'value': 'PUBLIC_ASSIGNED', 'count': 1}])
        self.assertEqual(data['Function'], [{'value': 'WrMultCoils', 'count': 1}])
        self.assertEqual(data['Unit ID'], [{'value': '1', 'count': 1}])

    def test_get_aggregation_data_sqlite_dnp3_type_bugfix_and_fallback_addrs(self):
        # REGRESSION: dnp3's 'Type' column previously always rendered empty
        # (same class of bug as modbus Category above - no dnp3 branch, fell
        # through to e.dns?.rrtype, always undefined for dnp3 events).
        eve_file = self._write_eve('eve_dnp3.json', [
            {'event_type': 'dnp3', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '10.0.0.8',
             'dest_ip': '10.0.0.3', 'dest_port': 20000, 'proto': 'TCP',
             'dnp3': {'type': 'unsolicited_response', 'src': 4, 'dst': 3,
                      'application': {'function_code': 130}}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'dnp3')
        self.assertEqual(data['Type'], [{'value': 'unsolicited_response', 'count': 1}])
        self.assertEqual(data['Source Addr'], [{'value': '4', 'count': 1}])
        self.assertEqual(data['Dest Addr'], [{'value': '3', 'count': 1}])
        self.assertEqual(data['Function'], [{'value': '130', 'count': 1}])

    def test_get_aggregation_data_sqlite_pgsql_query_bugfix_and_ssl_threeway(self):
        # REGRESSION: pgsql's 'Query' column previously always rendered
        # empty - a literal duplicate `case 'Query':` in extractValue meant
        # the first (dns-only) case always won over the already-correct,
        # unreachable pgsql-branching second case.
        eve_file = self._write_eve('eve_pgsql.json', [
            {'event_type': 'pgsql', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 5432, 'proto': 'TCP',
             'pgsql': {'request': {'simple_query': 'SELECT 1'},
                       'response': {'command_completed': 'SELECT 1', 'data_rows': 1, 'ssl_accepted': False}}},
            {'event_type': 'pgsql', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 5432, 'proto': 'TCP',
             'pgsql': {'request': {'message': 'SSL Request'}, 'response': {'ssl_accepted': True}}},
            {'event_type': 'pgsql', 'timestamp': '2026-01-01T00:00:02', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 5432, 'proto': 'TCP',
             'pgsql': {}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'pgsql')
        self.assertIn({'value': 'SELECT 1', 'count': 1}, data['Query'])
        self.assertIn({'value': '(empty)', 'count': 2}, data['Query'])
        self.assertIn({'value': '1', 'count': 1}, data['Rows'])
        # SSL: three-way transform - NULL -> '', true -> 'Yes', false -> 'No'.
        self.assertIn({'value': 'No', 'count': 1}, data['SSL'])
        self.assertIn({'value': 'Yes', 'count': 1}, data['SSL'])
        self.assertIn({'value': '(empty)', 'count': 1}, data['SSL'])

    def test_get_aggregation_data_sqlite_quic(self):
        # REGRESSION: quic (10% of all events in a real analysis) had no
        # AGGREGATION_JSON_PATHS entry at all, so /api/aggregation-data
        # returned {} unconditionally - this must return real data now.
        #
        # ja3/ja3s are objects ({"hash": ..., "string": ...}) in Suricata's
        # real eve.json output, not plain strings - confirmed against real
        # local data. An earlier version of this fix extracted the whole
        # object, which the frontend then rendered as the literal text
        # "[object Object]" instead of the hash.
        eve_file = self._write_eve('eve_quic.json', [
            {'event_type': 'quic', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'UDP',
             'quic': {'sni': 'example.com', 'version': '1',
                      'ja3': {'hash': 'abc', 'string': '771,4866,...'},
                      'ja3s': {'hash': 'def', 'string': '771,4866,...'}}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'quic')
        self.assertEqual(data['SNI'], [{'value': 'example.com', 'count': 1}])
        self.assertEqual(data['QUIC Version'], [{'value': '1', 'count': 1}])
        self.assertEqual(data['JA3'], [{'value': 'abc', 'count': 1}])
        self.assertEqual(data['JA3S'], [{'value': 'def', 'count': 1}])

    def test_get_aggregation_data_sqlite_rfb_nested_object_fields(self):
        # REGRESSION: same class of bug as quic's ja3/ja3s above. rfb's
        # client/server_protocol_version are {major, minor} objects, and
        # security_type is nested under 'authentication' - not a top-level
        # field - in Suricata's real eve.json (rust/src/rfb/logger.rs),
        # confirmed against a real VNC/RFB capture. The original
        # implementation assumed flat top-level fields, which was never
        # caught because no real sample was available to test against at
        # the time; 'Security Type' silently aggregated to nothing but
        # empty/default values as a result.
        eve_file = self._write_eve('eve_rfb.json', [
            {'event_type': 'rfb', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'rfb': {'client_protocol_version': {'major': '003', 'minor': '008'},
                     'server_protocol_version': {'major': '003', 'minor': '008'},
                     'authentication': {'security_type': 2, 'security_result': 'OK'}}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'rfb')
        # Grouped by major version only - see the AGGREGATION_JSON_PATHS
        # comment for why (same limitation as ike's 'IKE Version').
        self.assertEqual(data['Client Version'], [{'value': '003', 'count': 1}])
        self.assertEqual(data['Server Version'], [{'value': '003', 'count': 1}])
        self.assertEqual(data['Security Type'], [{'value': '2', 'count': 1}])

    def test_get_aggregation_data_sqlite_enip_command_status_fallback(self):
        # enip (EtherNet/IP) had zero column/aggregation support at all -
        # confirmed against Suricata's own logger source (rust/src/enip/
        # logger.rs). Command/Status prefer request/response.command and
        # response/request.status respectively, matching buildRowForEvent's
        # own fallback order exactly.
        eve_file = self._write_eve('eve_enip.json', [
            {'event_type': 'enip', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'enip': {'request': {'command': 'RegisterSession'},
                      'response': {'command': 'RegisterSession', 'status': 'Success'}}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'enip')
        self.assertEqual(data['Command'], [{'value': 'RegisterSession', 'count': 1}])
        self.assertEqual(data['Status'], [{'value': 'Success', 'count': 1}])

    def test_get_aggregation_data_sqlite_ntp_numeric_fields(self):
        # ntp had zero column/aggregation support at all - confirmed against
        # Suricata's own logger source (rust/src/ntp/log.rs). version/mode/
        # stratum are numeric and need CAST TEXT (like other numeric
        # aggregation columns), reference_id is already a formatted string.
        eve_file = self._write_eve('eve_ntp.json', [
            {'event_type': 'ntp', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'UDP',
             'ntp': {'version': 4, 'mode': 3, 'stratum': 2, 'reference_id': '0a:0a:0a:01'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'ntp')
        self.assertEqual(data['Version'], [{'value': '4', 'count': 1}])
        self.assertEqual(data['Mode'], [{'value': '3', 'count': 1}])
        self.assertEqual(data['Stratum'], [{'value': '2', 'count': 1}])
        self.assertEqual(data['Reference ID'], [{'value': '0a:0a:0a:01', 'count': 1}])

    def test_get_aggregation_data_sqlite_websocket(self):
        # New in Suricata 8 - confirmed against rust/src/websocket/logger.rs.
        # 'Fin' needs a value transform matching extractValue's
        # String(e.websocket.fin) exactly ("true"/"false", not "Yes"/"No"
        # like flow.Alerted/pgsql.SSL).
        eve_file = self._write_eve('eve_websocket.json', [
            {'event_type': 'websocket', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'websocket': {'fin': True, 'opcode': 'text', 'payload_printable': 'hello'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'websocket')
        self.assertEqual(data['Opcode'], [{'value': 'text', 'count': 1}])
        self.assertEqual(data['Fin'], [{'value': 'true', 'count': 1}])

    def test_get_aggregation_data_sqlite_pop3(self):
        # New in Suricata 8 - confirmed against rust/src/pop3/logger.rs.
        eve_file = self._write_eve('eve_pop3.json', [
            {'event_type': 'pop3', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'pop3': {'request': {'command': 'USER', 'args': ['alice']},
                      'response': {'success': True, 'status': 'OK'}}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'pop3')
        self.assertEqual(data['Command'], [{'value': 'USER', 'count': 1}])
        self.assertEqual(data['Status'], [{'value': 'OK', 'count': 1}])

    def test_get_aggregation_data_sqlite_mdns(self):
        # New in Suricata 8 - reuses dns's V3 queries[] array shape almost
        # verbatim (confirmed against rust/src/mdns/log.rs).
        eve_file = self._write_eve('eve_mdns.json', [
            {'event_type': 'mdns', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'UDP',
             'mdns': {'type': 'response', 'queries': [{'rrname': 'printer.local', 'rrtype': 'A'}]}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'mdns')
        self.assertEqual(data['Query'], [{'value': 'printer.local', 'count': 1}])
        self.assertEqual(data['Type'], [{'value': 'A', 'count': 1}])

    def test_get_aggregation_data_sqlite_ldap_not_supported(self):
        # ldap is intentionally excluded from AGGREGATION_JSON_PATHS - same
        # category as mqtt: its request/response detail lives under a
        # differently-named sub-object per operation type
        # (bind_request/search_request/.../bind_response/...), with no
        # static JSON path representation. Must degrade gracefully to {}.
        eve_file = self._write_eve('eve_ldap.json', [
            {'event_type': 'ldap', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'ldap': {'request': {'message_id': 1, 'operation': 'bind_request'}}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'ldap')
        self.assertEqual(data, {})

    def test_get_aggregation_data_sqlite_arp(self):
        # New in Suricata 8 - a decode-layer packet logger (not app-layer),
        # confirmed against src/output-json-arp.c. Ships disabled by default
        # (deliberately not force-enabled - see _enable_eve_log_arp).
        eve_file = self._write_eve('eve_arp.json', [
            {'event_type': 'arp', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'ARP',
             'arp': {'opcode': 'request', 'src_mac': 'aa:bb:cc:dd:ee:ff',
                     'dest_mac': '00:00:00:00:00:00'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'arp')
        self.assertEqual(data['Opcode'], [{'value': 'request', 'count': 1}])
        self.assertEqual(data['Src MAC'], [{'value': 'aa:bb:cc:dd:ee:ff', 'count': 1}])
        self.assertEqual(data['Dest MAC'], [{'value': '00:00:00:00:00:00', 'count': 1}])

    def test_get_aggregation_data_sqlite_dhcp_dual_path_fallback(self):
        # dhcp's 'DHCP Type' column falls back from dhcp_type to the more
        # generic top-level 'type' field, matching extractValue's own
        # dh.dhcp_type || dh.type fallback.
        eve_file = self._write_eve('eve_dhcp.json', [
            {'event_type': 'dhcp', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '10.0.0.1',
             'dest_ip': '10.0.0.2', 'proto': 'UDP',
             'dhcp': {'dhcp_type': 'ack', 'client_mac': 'aa:bb:cc:dd:ee:ff', 'assigned_ip': '10.0.0.50', 'hostname': 'laptop'}},
            {'event_type': 'dhcp', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '10.0.0.1',
             'dest_ip': '10.0.0.3', 'proto': 'UDP',
             'dhcp': {'type': 'request'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'dhcp')
        self.assertIn({'value': 'ack', 'count': 1}, data['DHCP Type'])
        self.assertIn({'value': 'request', 'count': 1}, data['DHCP Type'])
        self.assertIn({'value': 'aa:bb:cc:dd:ee:ff', 'count': 1}, data['Client MAC'])

    def test_get_aggregation_data_sqlite_smtp_rcpt_to_array_join(self):
        # smtp's 'Rcpt To' is a JSON array field, needing the same
        # json_each/group_concat treatment as filealerts.Tags.
        eve_file = self._write_eve('eve_smtp.json', [
            {'event_type': 'smtp', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'smtp': {'helo': 'mail.example.com', 'mail_from': 'a@example.com',
                      'rcpt_to': ['b@example.com', 'c@example.com']}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'smtp')
        self.assertEqual(data['Helo'], [{'value': 'mail.example.com', 'count': 1}])
        self.assertEqual(data['Rcpt To'], [{'value': 'b@example.com, c@example.com', 'count': 1}])

    def test_get_aggregation_data_sqlite_sip_code_cast_text(self):
        # sip's 'SIP Code' is numeric in the raw JSON but must aggregate/
        # display as text, matching extractValue's String(sp.code) treatment.
        eve_file = self._write_eve('eve_sip.json', [
            {'event_type': 'sip', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'UDP', 'sip': {'code': 200, 'reason': 'OK'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'sip')
        self.assertEqual(data['SIP Code'], [{'value': '200', 'count': 1}])

    def test_get_aggregation_data_sqlite_dcerpc_array_index_path(self):
        # dcerpc's 'Interface UUID' extracts interfaces[0].uuid - confirms
        # SQLite json_extract's array-index path syntax works as expected.
        eve_file = self._write_eve('eve_dcerpc.json', [
            {'event_type': 'dcerpc', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'dcerpc': {'interfaces': [{'uuid': '12345678-1234-1234-1234-123456789abc'}],
                        'request': {'opnum': 5}, 'call_id': 3}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'dcerpc')
        self.assertEqual(data['Interface UUID'], [{'value': '12345678-1234-1234-1234-123456789abc', 'count': 1}])
        self.assertEqual(data['Opnum'], [{'value': '5', 'count': 1}])
        self.assertEqual(data['Call ID'], [{'value': '3', 'count': 1}])

    def test_get_aggregation_data_sqlite_ssh_coalesce_client_or_server(self):
        eve_file = self._write_eve('eve_ssh.json', [
            {'event_type': 'ssh', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'ssh': {'client': {'software_version': 'OpenSSH_8.9'}, 'server': {'software_version': 'OpenSSH_9.2'}}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'ssh')
        self.assertEqual(data['Client Version'], [{'value': 'OpenSSH_8.9', 'count': 1}])
        self.assertEqual(data['Server Version'], [{'value': 'OpenSSH_9.2', 'count': 1}])

    def test_get_aggregation_data_sqlite_mqtt_not_supported(self):
        # mqtt is intentionally excluded from AGGREGATION_JSON_PATHS (its
        # fields are dynamically keyed by message subtype, with no static
        # JSON path representation) - must degrade gracefully to {}, not error.
        eve_file = self._write_eve('eve_mqtt.json', [
            {'event_type': 'mqtt', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP', 'mqtt': {'connect': {'client_id': 'device1'}}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'mqtt')
        self.assertEqual(data, {})

    def test_get_aggregation_data_sqlite_ftp_array_fields(self):
        # REGRESSION: ftp ('Completion Code'/'Reply', both JSON arrays in
        # Suricata's real eve.json shape) previously had no
        # AGGREGATION_JSON_PATHS entry at all, same class of gap as quic/dhcp.
        eve_file = self._write_eve('eve_ftp.json', [
            {'event_type': 'ftp', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'dest_port': 21, 'proto': 'TCP',
             'ftp': {'command': 'STOR', 'command_data': 'secret.txt',
                     'completion_code': ['150', '226'], 'reply': ['Accepted', 'Transfer complete']}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'ftp')
        self.assertEqual(data['Command'], [{'value': 'STOR', 'count': 1}])
        self.assertEqual(data['Command Data'], [{'value': 'secret.txt', 'count': 1}])
        self.assertEqual(data['Completion Code'], [{'value': '150, 226', 'count': 1}])
        self.assertEqual(data['Reply'], [{'value': 'Accepted, Transfer complete', 'count': 1}])

    def test_get_aggregation_data_sqlite_anomaly_event_field_bugfix(self):
        # REGRESSION: anomaly's real Suricata field is 'event' (e.g.
        # "APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION"), not 'message' -
        # 'message' has never existed in Suricata's anomaly eve.json schema
        # and both socrates.js's Detail case and this file's
        # _all_events_detail_expr previously referenced it, always silently
        # returning empty for every anomaly event, in the merged view too.
        eve_file = self._write_eve('eve_anomaly.json', [
            {'event_type': 'anomaly', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP',
             'anomaly': {'event': 'APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION',
                         'type': 'applayer', 'layer': 'proto_detect', 'app_proto': 'ftp'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'anomaly')
        self.assertEqual(data['Event'], [{'value': 'APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION', 'count': 1}])
        self.assertEqual(data['Type'], [{'value': 'applayer', 'count': 1}])
        self.assertEqual(data['Layer'], [{'value': 'proto_detect', 'count': 1}])
        self.assertEqual(data['App Proto'], [{'value': 'ftp', 'count': 1}])
        # Merged 'all events' view's Detail column must use the same real field.
        merged = db.get_aggregation_data_sqlite(self.db_file, None)
        detail_values = {e['value'] for e in merged['Detail']}
        self.assertIn('APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION', detail_values)

    def test_get_aggregation_data_sqlite_with_event_type_filter(self):
        eve_file = self._write_eve('eve_mixed.json', [
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP', 'alert': {'category': 'A', 'severity': 1}},
            {'event_type': 'dns', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '3.3.3.3',
             'dest_ip': '4.4.4.4', 'proto': 'UDP', 'dns': {'rrname': 'x.com', 'rrtype': 'A'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'alert')
        self.assertEqual(data['Category'], [{'value': 'A', 'count': 1}])
        self.assertNotIn('Query', data)

    def test_get_aggregation_data_sqlite_with_q(self):
        eve_file = self._write_eve('eve_q.json', [
            {'event_type': 'dns', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'UDP', 'dns': {'rrname': 'example.com', 'rrtype': 'A'}},
            {'event_type': 'dns', 'timestamp': '2026-01-01T00:00:01', 'src_ip': '3.3.3.3',
             'dest_ip': '4.4.4.4', 'proto': 'UDP', 'dns': {'rrname': 'other.org', 'rrtype': 'A'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'dns', q='example')
        self.assertEqual(data['Query'], [{'value': 'example.com', 'count': 1}])

    def test_get_aggregation_data_sqlite_merged_all_events(self):
        """event_type=None (the merged 'all events' view) must now return
        real Type/Detail aggregations (previously always {}) alongside the
        existing event_type-agnostic real columns."""
        eve_file = self._write_eve('eve_merged_agg.json', [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'proto': 'TCP', 'src_ip': '1.1.1.1'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'proto': 'TCP', 'src_ip': '2.2.2.2'},
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:02', 'proto': 'TCP', 'alert': {'signature': 'ET TEST sig'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, None)
        self.assertIn('Type', data)
        self.assertIn('Detail', data)
        type_counts = {e['value']: e['count'] for e in data['Type']}
        self.assertEqual(type_counts, {'FLOW': 2, 'ALERT': 1})
        detail_values = {e['value'] for e in data['Detail']}
        self.assertIn('ET TEST sig', detail_values)

    def test_get_aggregation_data_sqlite_merged_all_events_new_protocol_details(self):
        """The merged view's Detail column for the newly-supported protocols,
        including sip's CASE-based method-vs-code branching (the trickiest
        of the new _all_events_detail_expr additions)."""
        eve_file = self._write_eve('eve_merged_new_protocols.json', [
            {'event_type': 'quic', 'timestamp': '2026-01-01T00:00:00', 'proto': 'UDP',
             'quic': {'sni': 'example.com'}},
            {'event_type': 'sip', 'timestamp': '2026-01-01T00:00:01', 'proto': 'UDP',
             'sip': {'method': 'INVITE', 'uri': 'sip:bob@example.com'}},
            {'event_type': 'sip', 'timestamp': '2026-01-01T00:00:02', 'proto': 'UDP',
             'sip': {'code': 200, 'reason': 'OK'}},
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, None)
        detail_values = {e['value'] for e in data['Detail']}
        self.assertIn('example.com', detail_values)
        self.assertIn('INVITE sip:bob@example.com', detail_values)
        self.assertIn('200 OK', detail_values)
        # Protocol is a pre-existing event_type-agnostic real column - must
        # still work unchanged for the merged case.
        self.assertEqual(data['Protocol'], [{'value': 'UDP', 'count': 3}])

    def test_get_aggregation_data_sqlite_caps_to_top_n(self):
        eve_file = self._write_eve('eve_many_categories.json', [
            {'event_type': 'alert', 'timestamp': '2026-01-01T00:00:00', 'src_ip': '1.1.1.1',
             'dest_ip': '2.2.2.2', 'proto': 'TCP', 'alert': {'category': f'Cat{i}', 'severity': 1}}
            for i in range(15)
        ])
        db.create_sqlite_db(self.db_file, eve_file)
        data = db.get_aggregation_data_sqlite(self.db_file, 'alert', top_n=10)
        self.assertEqual(len(data['Category']), 10, 'must cap to top_n, matching CONFIG.AGGREGATION_TOP_N')

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
        self.assertEqual(fa['filealerts']['author'], 'test')
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

    def test_merged_file_metadata_searchable_via_fts5(self):
        """REGRESSION: file_metadata.json is merged into a fileinfo event's
        json_data via a direct UPDATE, bypassing the events_fts virtual
        table entirely. events_fts uses content='events' (external
        content), which does NOT auto-sync on changes to the content table
        - a stale comment claimed otherwise. Without an explicit
        delete+reinsert against events_fts, the merged metadata was
        findable via events.json_data/LIKE but never via an FTS5 MATCH
        search."""
        import json as json_mod
        with open(self.eve_file, 'a') as f:
            f.write(json_mod.dumps({
                'event_type': 'fileinfo',
                'timestamp': '2026-01-01T00:00:04',
                'fileinfo': {'sha256': 'c' * 64},
            }) + '\n')
        meta_file = self.db_file.replace('events.db', 'file_metadata.json')
        with open(meta_file, 'w') as f:
            json_mod.dump({'c' * 64: {'entropy': 7.9, 'unique_marker': 'findme_via_fts_merge'}}, f)
        db.create_sqlite_db(self.db_file, self.eve_file)
        events = db.query_events_sqlite(self.db_file, q='findme_via_fts_merge')
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['fileinfo']['metadata']['unique_marker'], 'findme_via_fts_merge')


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
        self.assertEqual(fa['filealerts']['author'], 'test')


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


class TestBackwardCompatibility(unittest.TestCase):
    """Test behavior with pre-v1.0.0 database schemas (no sigma_alerts table)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.tmpdir, 'events.db')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _create_old_schema(self):
        """Create a database with only the pre-v1.0.0 events table."""
        conn = sqlite3.connect(self.db_file)
        conn.executescript('''
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
                json_data TEXT
            );
            CREATE INDEX idx_event_type ON events(event_type);
            CREATE INDEX idx_timestamp ON events(timestamp);
            CREATE INDEX idx_event_type_timestamp ON events(event_type, timestamp);
        ''')
        conn.commit()
        conn.close()

    def test_query_sigma_alerts_on_old_schema_returns_empty(self):
        """query_sigma_alerts_sqlite must return [] when sigma_alerts table is missing."""
        self._create_old_schema()
        alerts = db.query_sigma_alerts_sqlite(self.db_file)
        self.assertEqual(alerts, [])

    def test_get_sigma_stats_on_old_schema_returns_empty(self):
        """get_sigma_stats_sqlite must return {} when sigma_alerts table is missing."""
        self._create_old_schema()
        stats = db.get_sigma_stats_sqlite(self.db_file)
        self.assertEqual(stats, {})

    def test_query_sigma_alerts_when_acknowledged_alerts_table_missing(self):
        """REGRESSION: an analysis created between v2.0.0 (sigma_alerts
        added) and this feature's release has a sigma_alerts table but no
        acknowledged_alerts table yet - nothing on this read path calls
        _init_db to lazily create it (that's a write-path-only convention).
        The acknowledged-exclusion condition inside _sigma_alert_where must
        not reference acknowledged_alerts unconditionally, or every such
        analysis would hit 'no such table: acknowledged_alerts' (caught
        broadly as sqlite3.OperationalError) and silently show zero alerts
        until something else happened to create the table first."""
        self._create_old_schema()
        db.insert_sigma_alerts(self.db_file, [{
            'timestamp': '2026-01-01T00:00:00', 'rule_title': 'r', 'rule_id': 'r1',
            'severity': 'high', 'level': 'high',
        }])
        # insert_sigma_alerts calls _init_db, which would create
        # acknowledged_alerts too - drop it back out to reproduce the
        # narrower window where sigma_alerts exists but it doesn't.
        conn = sqlite3.connect(self.db_file)
        conn.execute('DROP TABLE acknowledged_alerts')
        conn.commit()
        conn.close()

        alerts = db.query_sigma_alerts_sqlite(self.db_file)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(db.get_sigma_alert_count_sqlite(self.db_file), 1)

    def test_query_events_when_acknowledged_alerts_table_missing(self):
        """Same regression as test_query_sigma_alerts_when_acknowledged_alerts_table_missing,
        for the events side."""
        self._create_old_schema()
        conn = sqlite3.connect(self.db_file)
        conn.execute('''INSERT INTO events (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, json_data)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     ('alert', '2026-01-01T00:00:00', '1.2.3.4', 1234, '5.6.7.8', 80, 'TCP', '', '{"event_type":"alert"}'))
        conn.commit()
        conn.close()

        events = db.query_events_sqlite(self.db_file)
        self.assertEqual(len(events), 1)
        self.assertEqual(db.get_event_count_sqlite(self.db_file), 1)

    def test_query_events_on_old_schema_still_works(self):
        """query_events_sqlite must still return events from an old-schema database."""
        self._create_old_schema()
        conn = sqlite3.connect(self.db_file)
        conn.execute('''INSERT INTO events (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, json_data)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     ('alert', '2026-01-01T00:00:00', '1.2.3.4', 1234, '5.6.7.8', 80, 'TCP', '', '{"event_type":"alert"}'))
        conn.commit()
        conn.close()
        events = db.query_events_sqlite(self.db_file)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_type'], 'alert')

    def test_insert_sigma_alerts_lazily_creates_table(self):
        """insert_sigma_alerts must create the missing sigma_alerts table on first call."""
        self._create_old_schema()
        db.insert_sigma_alerts(self.db_file, [{
            'timestamp': '2026-01-01T00:00:00',
            'rule_title': 'Test Rule',
            'rule_id': 'r1',
            'severity': 'high',
            'level': 'high',
            'logsource': 'windows',
            'tags': '[]',
            'mitre_techniques': '[]',
            'original_log': '{}',
            'json_data': '{}',
        }])
        conn = sqlite3.connect(self.db_file)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sigma_alerts'")
        self.assertIsNotNone(cursor.fetchone(), 'sigma_alerts table must be created lazily')
        conn.close()

        # Verify query works after lazy creation
        alerts = db.query_sigma_alerts_sqlite(self.db_file)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['rule_title'], 'Test Rule')


class TestFileAnalysisDBTimeout(unittest.TestCase):
    @unittest.mock.patch('subprocess.run')
    def test_file_command_timeout_does_not_crash(self, mock_run):
        """TimeoutExpired from `file` must be caught during DB creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = os.path.join(tmpdir, 'evil.exe')
            with open(tmp_file, 'wb') as f:
                f.write(b'MZ' + b'\x00' * 62)
            db_file = os.path.join(tmpdir, 'file_events.db')
            mock_run.side_effect = subprocess.TimeoutExpired('file', 10)
            try:
                db.create_file_analysis_db(
                    db_file, tmp_file, [],
                    file_md5='a' * 32, file_sha1='b' * 40, file_sha256='c' * 64
                )
            except subprocess.TimeoutExpired:
                self.fail('create_file_analysis_db raised TimeoutExpired')
            self.assertTrue(os.path.exists(db_file))


class TestRelatedFilePath(unittest.TestCase):
    def test_helper_avoids_substring_replace_bug(self):
        """_related_file_path must not treat 'events.db' as a substring."""
        db_path = '/tmp/events.db-backup/analysis/events.db'
        self.assertEqual(
            db._related_file_path(db_path, 'yara_matches.json'),
            '/tmp/events.db-backup/analysis/yara_matches.json'
        )

    def test_yara_matches_found_when_dir_contains_events_db(self):
        """YARA matches must be found even when the parent directory contains 'events.db'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analysis_dir = os.path.join(tmpdir, 'events.db-backup', 'analysis')
            os.makedirs(analysis_dir)
            db_file = os.path.join(analysis_dir, 'events.db')
            eve_file = os.path.join(analysis_dir, 'eve.json')

            with open(eve_file, 'w') as f:
                f.write(json.dumps({
                    'event_type': 'fileinfo',
                    'timestamp': '2026-01-01T00:00:00',
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

            yara_file = os.path.join(analysis_dir, 'yara_matches.json')
            with open(yara_file, 'w') as f:
                json.dump([{
                    'rule_name': 'MALWARE_Test',
                    'sha256': 'a' * 64,
                    'tags': ['malware'],
                    'meta': {'author': 'test'},
                    'strings': [],
                    'file_id': 'file.1',
                }], f)

            db.create_sqlite_db(db_file, eve_file)
            events = db.query_events_sqlite(db_file, event_type='filealerts')
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]['filealerts']['rule_name'], 'MALWARE_Test')


if __name__ == '__main__':
    unittest.main(verbosity=2)
