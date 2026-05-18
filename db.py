#!/usr/bin/env python3
"""SQLite database layer for OhMyPCAP."""

import json
import os
import sqlite3
from contextlib import contextmanager

from models import (
    get_app_proto,
    get_dest_ip,
    get_dest_port,
    get_event_type,
    get_protocol,
    get_src_ip,
    get_src_port,
    get_timestamp,
)
import config

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
CREATE INDEX IF NOT EXISTS idx_event_type_timestamp ON events(event_type, timestamp);

'''


def _has_fts5(conn):
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events_fts'")
    return cursor.fetchone() is not None


def _sanitize_like(term):
    return '%' + term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'


def _escape_fts5(term):
    tokens = term.split()
    return ' '.join('"' + t.replace('"', '""') + '"' for t in tokens)


def _build_search_terms(q):
    if q is None:
        return []
    if isinstance(q, str):
        return [q.strip()[:200]] if q.strip() else []
    if isinstance(q, list):
        return [x.strip()[:200] for x in q if x.strip()]
    return []


@contextmanager
def _db_connection(db_path):
    conn = sqlite3.connect(db_path, timeout=config.SQLITE_TIMEOUT_SECONDS)
    conn.execute('PRAGMA busy_timeout = 30000;')
    try:
        yield conn
    finally:
        conn.close()


def create_sqlite_db(db_path, eve_file):
    with _db_connection(db_path) as conn:
        conn.execute('PRAGMA journal_mode = WAL;')
        conn.execute('PRAGMA synchronous = NORMAL;')
        conn.executescript(SQLITE_SCHEMA)

        try:
            conn.execute('''
                CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                    json_data,
                    content='events',
                    content_rowid='id'
                )
            ''')
            has_fts = True
        except Exception:
            has_fts = False

        fileinfo_by_sha256 = {}

        with open(eve_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    event_type = get_event_type(event)
                    timestamp = get_timestamp(event)

                    src_ip = get_src_ip(event)
                    src_port = get_src_port(event)
                    dest_ip = get_dest_ip(event)
                    dest_port = get_dest_port(event)
                    protocol = get_protocol(event)
                    app_proto = get_app_proto(event)

                    cur = conn.execute(
                        '''INSERT INTO events (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, json_data)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, line)
                    )

                    if has_fts:
                        conn.execute(
                            'INSERT INTO events_fts (rowid, json_data) VALUES (?, ?)',
                            (cur.lastrowid, line)
                        )

                    # Index fileinfo events by SHA256 for YARA correlation
                    if event_type == 'fileinfo':
                        sha256 = event.get('fileinfo', {}).get('sha256')
                        if sha256:
                            fileinfo_by_sha256[sha256] = event
                except json.JSONDecodeError:
                    continue

        # Create synthetic filealerts events from YARA matches correlated with fileinfo
        yara_file = db_path.replace('events.db', 'yara_matches.json')
        if os.path.exists(yara_file) and fileinfo_by_sha256:
            try:
                with open(yara_file, 'r') as f:
                    yara_matches = json.load(f)
                for match in yara_matches:
                    sha256 = match.get('sha256', '')
                    fileinfo = fileinfo_by_sha256.get(sha256)
                    if not fileinfo:
                        continue
                    synthetic_event = {
                        'event_type': 'filealerts',
                        'timestamp': get_timestamp(fileinfo),
                        'src_ip': get_src_ip(fileinfo),
                        'src_port': get_src_port(fileinfo),
                        'dest_ip': get_dest_ip(fileinfo),
                        'dest_port': get_dest_port(fileinfo),
                        'proto': get_protocol(fileinfo),
                        'app_proto': get_app_proto(fileinfo),
                        'filealerts': {
                            'rule_name': match.get('rule_name', ''),
                            'classification': match.get('classification', 'informational'),
                            'tags': match.get('tags', []),
                            'sha256': sha256,
                            'file_id': match.get('file_id', ''),
                            'strings': match.get('strings', []),
                            'meta': match.get('meta', {}),
                        },
                    }
                    synthetic_line = json.dumps(synthetic_event, separators=(',', ':'))
                    cur = conn.execute(
                        '''INSERT INTO events (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, json_data)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (
                            'filealerts',
                            synthetic_event['timestamp'],
                            synthetic_event['src_ip'],
                            synthetic_event['src_port'],
                            synthetic_event['dest_ip'],
                            synthetic_event['dest_port'],
                            synthetic_event['proto'],
                            synthetic_event['app_proto'],
                            synthetic_line,
                        )
                    )
                    if has_fts:
                        conn.execute(
                            'INSERT INTO events_fts (rowid, json_data) VALUES (?, ?)',
                            (cur.lastrowid, synthetic_line)
                        )
            except (json.JSONDecodeError, TypeError) as e:
                print(f'Warning: could not parse YARA matches: {e}')

        conn.execute('PRAGMA optimize;')
        conn.commit()


def create_file_analysis_db(db_path, file_path, yara_matches, file_md5, file_sha1, file_sha256, magic_desc=''):
    """Create events.db for a standalone file scan (non-PCAP).

    Inserts one synthetic fileinfo event and zero or more filealerts events
    correlated by SHA256.
    """
    import subprocess
    from datetime import datetime, timezone

    if not magic_desc:
        try:
            result = subprocess.run(
                ['file', '--brief', file_path],
                capture_output=True, text=True, timeout=config.FILE_COMMAND_TIMEOUT
            )
            if result.returncode == 0:
                magic_desc = result.stdout.strip()
        except (FileNotFoundError, PermissionError) as e:
            print(f'Warning: could not run file command: {e}')

    timestamp = datetime.now(timezone.utc).isoformat()
    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    with _db_connection(db_path) as conn:
        conn.execute('PRAGMA journal_mode = WAL;')
        conn.execute('PRAGMA synchronous = NORMAL;')
        conn.executescript(SQLITE_SCHEMA)

        try:
            conn.execute('''
                CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                    json_data,
                    content='events',
                    content_rowid='id'
                )
            ''')
            has_fts = True
        except Exception:
            has_fts = False

        # Insert synthetic fileinfo event
        fileinfo_event = {
            'event_type': 'fileinfo',
            'timestamp': timestamp,
            'src_ip': '',
            'src_port': 0,
            'dest_ip': '',
            'dest_port': 0,
            'proto': '',
            'app_proto': '',
            'fileinfo': {
                'filename': filename,
                'size': file_size,
                'md5': file_md5,
                'sha1': file_sha1,
                'sha256': file_sha256,
                'magic': magic_desc,
            },
        }
        fileinfo_line = json.dumps(fileinfo_event, separators=(',', ':'))
        cur = conn.execute(
            '''INSERT INTO events (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, json_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            ('fileinfo', timestamp, '', 0, '', 0, '', '', fileinfo_line)
        )
        if has_fts:
            conn.execute(
                'INSERT INTO events_fts (rowid, json_data) VALUES (?, ?)',
                (cur.lastrowid, fileinfo_line)
            )

        # Insert synthetic filealerts events from YARA matches
        for match in yara_matches:
            synthetic_event = {
                'event_type': 'filealerts',
                'timestamp': timestamp,
                'src_ip': '',
                'src_port': 0,
                'dest_ip': '',
                'dest_port': 0,
                'proto': '',
                'app_proto': '',
                'filealerts': {
                    'rule_name': match.get('rule_name', ''),
                    'classification': match.get('classification', 'informational'),
                    'tags': match.get('tags', []),
                    'sha256': file_sha256,
                    'file_id': '',
                    'strings': match.get('strings', []),
                    'meta': match.get('meta', {}),
                },
            }
            synthetic_line = json.dumps(synthetic_event, separators=(',', ':'))
            cur = conn.execute(
                '''INSERT INTO events (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, json_data)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                ('filealerts', timestamp, '', 0, '', 0, '', '', synthetic_line)
            )
            if has_fts:
                conn.execute(
                    'INSERT INTO events_fts (rowid, json_data) VALUES (?, ?)',
                    (cur.lastrowid, synthetic_line)
                )

        conn.execute('PRAGMA optimize;')
        conn.commit()


def _build_where_conditions(terms, has_fts, event_type, event_type_col):
    """Build WHERE conditions and parameters for event queries.

    Args:
        terms: List of search terms (from _build_search_terms).
        has_fts: Whether FTS5 is available.
        event_type: Optional event_type filter value.
        event_type_col: Column reference ('event_type' or 'e.event_type').

    Returns:
        (conditions_list, params_list)
    """
    conditions = []
    params = []

    if terms and has_fts:
        fts_q = ' '.join(_escape_fts5(term) for term in terms)
        conditions.append('events_fts MATCH ?')
        params.append(fts_q)
    elif terms:
        for term in terms:
            conditions.append("json_data LIKE ? ESCAPE '\\'")
            params.append(_sanitize_like(term))

    if event_type:
        conditions.append(f'{event_type_col} = ?')
        params.append(event_type)

    return conditions, params


def query_events_sqlite(db_path, event_type=None, offset=0, limit=1000, q=None):
    with _db_connection(db_path) as conn:
        conn.row_factory = sqlite3.Row

        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False

        if terms and has_fts:
            select = 'SELECT e.json_data FROM events_fts JOIN events e ON events_fts.rowid = e.id'
            event_type_col = 'e.event_type'
        else:
            select = 'SELECT json_data FROM events'
            event_type_col = 'event_type'

        conditions, params = _build_where_conditions(terms, has_fts, event_type, event_type_col)

        sql = select
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)
        sql += ' ORDER BY timestamp LIMIT ? OFFSET ?'
        params = list(params) + [limit, offset]

        cursor = conn.execute(sql, params)
        return [json.loads(row['json_data']) for row in cursor.fetchall()]


def get_event_count_sqlite(db_path, event_type=None, q=None):
    with _db_connection(db_path) as conn:
        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False

        if terms and has_fts:
            select = 'SELECT COUNT(*) FROM events_fts JOIN events e ON events_fts.rowid = e.id'
            event_type_col = 'e.event_type'
        else:
            select = 'SELECT COUNT(*) FROM events'
            event_type_col = 'event_type'

        conditions, params = _build_where_conditions(terms, has_fts, event_type, event_type_col)

        sql = select
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)

        cursor = conn.execute(sql, params)
        return cursor.fetchone()[0]


def get_event_types_sqlite(db_path, q=None):
    with _db_connection(db_path) as conn:
        conn.row_factory = sqlite3.Row

        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False

        if terms and has_fts:
            select = 'SELECT e.event_type, COUNT(*) as cnt FROM events_fts JOIN events e ON events_fts.rowid = e.id'
            event_type_col = 'e.event_type'
        else:
            select = 'SELECT event_type, COUNT(*) as cnt FROM events'
            event_type_col = 'event_type'

        conditions, params = _build_where_conditions(terms, has_fts, None, event_type_col)

        sql = select
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)
        sql += f' GROUP BY {event_type_col} ORDER BY cnt DESC'

        cursor = conn.execute(sql, params)
        return {row['event_type']: row['cnt'] for row in cursor.fetchall()}



