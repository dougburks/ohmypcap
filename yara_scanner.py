#!/usr/bin/env python3
"""YARA scanning integration for OhMyPCAP.

YARA is optional. If installed, extracted files are scanned after Suricata
finishes. Rules are baked into Docker images; non-Docker deployments download
on first run if internet is available.
"""

import config
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request

from file_analyzer import analyze_file

YARA_FORGE_URL = (
    'https://github.com/YARAHQ/yara-forge/releases/latest/download/'
    'yara-forge-rules-full.zip'
)
BAKED_IN_YARA_FILE = '/usr/share/yara-rules/yara-rules-full.yar'
YARA_RULES_SUBDIR = 'yara-rules'
YARA_FORGE_FILENAME = 'yara-rules-full.yar'


def check_yara_executable():
    """Return True if the yara CLI is available."""
    return shutil.which('yara') is not None


def setup_yara_rules(data_dir=None):
    """Ensure YARA Forge rules are available.

    Priority:
    1. ~/ohmypcap-data/yara-rules/yara-rules-full.yar (already downloaded)
    2. Baked-in rules in /usr/share/yara-rules (Docker)
    3. Download latest YARA Forge release if internet is available

    Returns the rules file path or None if no rules are available.
    """
    if data_dir is None:
        data_dir = os.path.expanduser('~/ohmypcap-data')
    rules_file = os.path.join(data_dir, YARA_RULES_SUBDIR, YARA_FORGE_FILENAME)

    # Already downloaded/cached
    if os.path.isfile(rules_file):
        print('YARA Forge rules already present — using cached rules')
        return rules_file

    # Baked-in rules (Docker image)
    if os.path.isfile(BAKED_IN_YARA_FILE):
        print('Copying baked-in YARA Forge rules...')
        os.makedirs(os.path.dirname(rules_file), exist_ok=True)
        try:
            shutil.copy2(BAKED_IN_YARA_FILE, rules_file)
            print('Baked-in YARA Forge rules ready')
            return rules_file
        except OSError as e:
            print(f'Warning: could not copy baked-in rules: {e}')

    # Try to download
    if _has_internet_access():
        print('Internet access detected — downloading YARA Forge rules...')
        try:
            _download_yara_forge_rules(rules_file)
            print('YARA Forge rules downloaded successfully')
            return rules_file
        except (OSError, urllib.error.URLError) as e:
            print(f'Warning: could not download YARA Forge rules: {e}')
    else:
        print('No internet access detected — YARA Forge rules not available')

    return None


def _has_internet_access():
    from validators import is_host_reachable
    return is_host_reachable('github.com', 443, timeout=5)


def _download_yara_forge_rules(dest_file):
    """Download latest YARA Forge full rules ZIP and extract the .yar file."""
    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
    tmp_zip = dest_file + '.zip'

    req = urllib.request.Request(YARA_FORGE_URL, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=config.YARA_DOWNLOAD_TIMEOUT) as resp:
        with open(tmp_zip, 'wb') as f:
            f.write(resp.read())

    import zipfile
    with zipfile.ZipFile(tmp_zip, 'r') as zf:
        member = 'packages/full/yara-rules-full.yar'
        with zf.open(member) as src, open(dest_file, 'wb') as dst:
            dst.write(src.read())

    os.unlink(tmp_zip)


def _run_yara_with_index(rules_file, list_path, filestore_dir=None):
    """Run YARA against a rules file and return parsed matches."""
    if not os.path.isfile(rules_file):
        return []

    try:
        result = subprocess.run(
            [
                'yara', '-r', '-g', '-m', '-w',
                '-d', 'filename=""',
                '-d', 'filepath=""',
                '-d', 'extension=""',
                '-d', 'filetype=""',
                '-d', 'owner=""',
                '--scan-list', rules_file, list_path
            ],
            capture_output=True, text=True, timeout=config.YARA_SCAN_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        print(f'YARA scan timed out for {os.path.basename(rules_file)}')
        return []
    except (subprocess.CalledProcessError, OSError) as e:
        print(f'YARA scan error for {os.path.basename(rules_file)}: {e}')
        return []

    return _parse_yara_output(result.stdout, filestore_dir)


def _scan_with_indexes(list_path, rules_file, dedup_key_fn, filestore_dir=None):
    """Run YARA against the unified rule file and return deduplicated matches.

    Args:
        list_path: Path to the --scan-list file.
        rules_file: Path to the YARA Forge rules file.
        dedup_key_fn: Callable(match) -> hashable key for deduplication.
        filestore_dir: Optional filestore directory for _run_yara_with_index.

    Returns:
        List of match dicts.
    """
    all_matches = []
    seen = set()

    matches = _run_yara_with_index(rules_file, list_path, filestore_dir)
    for m in matches:
        key = dedup_key_fn(m)
        if key not in seen:
            seen.add(key)
            all_matches.append(m)

    return all_matches


def run_yara_scan(filestore_dir, rules_file):
    """Run YARA on extracted files and return list of matches.

    Each match is a dict:
        {
            'rule_name': str,
            'sha256': str,
            'file_path': str,
            'tags': list[str],
            'meta': dict,
        }
    """
    if not os.path.isdir(filestore_dir):
        return []

    # Collect all extracted files
    target_files = []
    for root, _dirs, files in os.walk(filestore_dir):
        for f in files:
            if f.endswith('.json'):
                continue
            target_files.append(os.path.join(root, f))

    if not target_files:
        return []

    # Write file list for --scan-list
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as list_file:
        for f in target_files:
            list_file.write(f + '\n')
        list_path = list_file.name

    try:
        return _scan_with_indexes(
            list_path, rules_file,
            dedup_key_fn=lambda m: (m['rule_name'], m['sha256']),
            filestore_dir=filestore_dir
        )
    finally:
        try:
            os.unlink(list_path)
        except OSError:
            pass


def _parse_yara_output(output, filestore_dir=None):
    """Parse YARA CLI output.

    YARA output formats (depending on flags):
        RuleName [Tags] [Metadata] FilePath   (with -g -m)
        RuleName [Tags] FilePath               (with -g)
        RuleName [Metadata] FilePath           (with -m)
        RuleName FilePath                      (default)

    Tags contain only simple identifiers (no '=').
    Metadata contains key=value pairs.
    """
    matches = []
    for line in output.strip().split('\n'):
        line = line.strip()
        if not line:
            continue

        # Try to extract file path (last token)
        parts = line.split()
        if len(parts) < 2:
            continue

        file_path = parts[-1]
        if filestore_dir:
            # Use commonpath to prevent directory traversal via path manipulation
            try:
                if os.path.commonpath([os.path.realpath(file_path), os.path.realpath(filestore_dir)]) != os.path.realpath(filestore_dir):
                    continue
            except ValueError:
                # Different drives / no common path
                continue

        # Derive SHA256 from filename (Suricata file-store names files by SHA256)
        sha256 = os.path.basename(file_path)
        if not re.match(r'^[a-f0-9]{64}$', sha256):
            # Fallback: try to read from metadata sidecar
            sha256 = _sha256_from_meta(file_path)

        rule_name = parts[0]

        # Extract the section between rule name and file path
        middle = line[len(rule_name):line.rfind(file_path)].strip()

        # Find all bracketed sections in the middle
        bracketed = re.findall(r'\[([^\]]*)\]', middle)

        tags = []
        meta = {}
        meta_section = ''

        for section in bracketed:
            # Tags sections have no '='; metadata sections do
            if '=' in section:
                meta_section = section
            else:
                tags = [t.strip() for t in section.split(',') if t.strip()]

        # Also handle metadata not in brackets (rare, but possible)
        # Remove bracketed parts from middle to get any remaining text
        remaining = re.sub(r'\[[^\]]*\]', '', middle).strip()
        if remaining and '=' in remaining:
            meta_section = remaining

        # Parse key=value pairs from metadata section
        for m in re.finditer(r'(\w+)="([^"]+)"', meta_section):
            meta[m.group(1)] = m.group(2)
        for m in re.finditer(r'(\w+)=([^\s"]+)', meta_section):
            if m.group(1) not in meta:
                meta[m.group(1)] = m.group(2)

        matches.append({
            'rule_name': rule_name,
            'sha256': sha256 or '',
            'file_path': file_path,
            'tags': tags,
            'meta': meta,
        })

    return matches


def _sha256_from_meta(file_path):
    """Try to read SHA256 from Suricata file-store metadata sidecar."""
    meta_path = file_path + '.json'
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'r') as f:
                data = json.load(f)
            return data.get('fileinfo', {}).get('sha256', '')
        except (json.JSONDecodeError, OSError):
            pass
    return ''


def write_yara_matches_json(dir_path, matches):
    """Write YARA match results to yara_matches.json in the analysis directory."""
    out_path = os.path.join(dir_path, 'yara_matches.json')
    with open(out_path, 'w') as f:
        json.dump(matches, f)


def run_yara_pipeline(dir_path, data_dir=None):
    """Full YARA pipeline: setup rules, scan filestore, write results.

    Also extracts metadata for files with zero YARA matches and writes
    file_metadata.json keyed by SHA256.

    Returns True if scanning completed (even with zero matches).
    Returns False if YARA is unavailable or rules could not be obtained.
    """
    if not check_yara_executable():
        print('YARA not available — skipping file scan')
        return False

    if data_dir is None:
        data_dir = os.path.expanduser('~/ohmypcap-data')
    rules_file = os.path.join(data_dir, YARA_RULES_SUBDIR, YARA_FORGE_FILENAME)
    if not os.path.isfile(rules_file):
        print(f'YARA Forge rules file not found: {rules_file}')
        return False

    filestore_dir = os.path.join(dir_path, 'filestore')
    if not os.path.isdir(filestore_dir):
        print('No extracted files to scan (filestore empty)')
        return False

    matches = run_yara_scan(filestore_dir, rules_file)
    write_yara_matches_json(dir_path, matches)

    # Extract metadata for files with zero YARA matches
    matched_sha256s = {m.get('sha256', '') for m in matches}
    file_metadata = {}
    for root, _dirs, files in os.walk(filestore_dir):
        for f in files:
            if f.endswith('.json'):
                continue
            file_path = os.path.join(root, f)
            sha256 = os.path.basename(file_path)
            if not re.match(r'^[a-f0-9]{64}$', sha256):
                continue
            if sha256 in matched_sha256s:
                continue
            metadata = analyze_file(file_path)
            if metadata.get('file_type') or metadata.get('entropy', 0) > 0:
                file_metadata[sha256] = metadata

    if file_metadata:
        meta_path = os.path.join(dir_path, 'file_metadata.json')
        try:
            with open(meta_path, 'w') as f:
                json.dump(file_metadata, f)
        except OSError as e:
            print(f'Warning: could not write file_metadata.json: {e}')

    return True


def scan_single_file(file_path, rules_file):
    """Run YARA on a single arbitrary file and return match results with hashes and metadata.

    Returns a tuple: (matches, sha256, md5, sha1, metadata)
        matches: list of dicts (same format as run_yara_scan)
        sha256: str
        md5: str
        sha1: str
        metadata: dict from file_analyzer.analyze_file
    """
    import hashlib

    if not os.path.isfile(file_path):
        return [], '', '', '', {}

    # Compute hashes
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(config.HASH_CHUNK_SIZE), b''):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)

    file_sha256 = sha256.hexdigest()
    file_md5 = md5.hexdigest()
    file_sha1 = sha1.hexdigest()

    # Extract metadata
    metadata = analyze_file(file_path)

    # Write file list for --scan-list
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as list_file:
        list_file.write(file_path + '\n')
        list_path = list_file.name

    try:
        def dedup_and_fix(m):
            m['sha256'] = file_sha256
            return (m['rule_name'], file_sha256)

        matches = _scan_with_indexes(list_path, rules_file, dedup_key_fn=dedup_and_fix)
        return matches, file_sha256, file_md5, file_sha1, metadata
    finally:
        try:
            os.unlink(list_path)
        except OSError:
            pass
