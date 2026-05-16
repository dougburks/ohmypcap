#!/usr/bin/env python3
"""YARA scanning integration for OhMyPCAP.

YARA is optional. If installed, extracted files are scanned after Suricata
finishes. Rules are baked into Docker images; non-Docker deployments download
on first run if internet is available.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request

NEO23X0_URL = 'https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip'
YARA_RULES_GIT_URL = 'https://github.com/YARA-Rules/rules.git'
BAKED_IN_YARA_DIR = '/usr/share/yara-rules'
NEO23X0_SUBDIR = 'neo23x0'
YARA_RULES_SUBDIR = 'yara-rules'
NEO23X0_ZIP_SUBDIR = 'signature-base-master/yara'
NEO23X0_INDEX = 'neo23x0-index.yar'

# Classification for YARA-Rules (by parent directory)
YARA_RULES_CONFIDENCE = {
    'malware': 'threat',
    'maldocs': 'threat',
    'exploit_kits': 'threat',
    'cve_rules': 'threat',
    'webshells': 'threat',
    'email': 'threat',
    'mobile_malware': 'threat',
    'antidebug_antivm': 'technique',
    'packers': 'technique',
    'capabilities': 'technique',
    'crypto': 'technique',
    'utils': 'informational',
    'deprecated': 'informational',
}

# Classification for Neo23x0 (by case-insensitive prefix)
# Ordered by priority (first match wins)
NEO23X0_CONFIDENCE = [
    # Known threat detections
    ('MALW_', 'threat'), ('MAL_', 'threat'), ('APT_', 'threat'), ('apt', 'threat'),
    ('RAT_', 'threat'), ('RANSOM_', 'threat'), ('TOOLKIT_', 'threat'),
    ('POS_', 'threat'), ('EXPL_', 'threat'), ('EQGRP_', 'threat'),
    ('EquationGroup', 'threat'), ('IMPLANT_', 'threat'), ('CobaltStrike', 'threat'),
    ('Empire', 'threat'), ('WEBSHELL', 'threat'), ('webshell', 'threat'),
    ('WebShell', 'threat'), ('Cloaked_', 'threat'), ('CRIME_', 'threat'),
    ('crime', 'threat'), ('FVEY', 'threat'), ('FSO', 'threat'),
    ('OPCLEAVER', 'threat'), ('Sofacy', 'threat'), ('Msfpayloads', 'threat'),
    ('CN_', 'threat'),
    # Technique / behavior indicators
    ('SUSP_', 'technique'), ('Suspicious', 'technique'), ('susp', 'technique'),
    ('GEN_', 'technique'), ('HACK_', 'technique'), ('HackTool', 'technique'),
    ('HKTL', 'technique'), ('PUA', 'technique'),
    # Informational / utility
    ('INFO_', 'informational'), ('Is', 'informational'), ('LOG_', 'informational'),
    ('sig', 'informational'),
]


def check_yara_executable():
    """Return True if the yara CLI is available."""
    return shutil.which('yara') is not None


def _extract_rule_names_from_file(yar_path):
    """Extract rule names from a YARA file using simple regex.

    Matches 'rule RuleName {' declarations, skipping commented lines.
    """
    names = []
    try:
        with open(yar_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Skip comment lines
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                    continue
                m = re.search(r'\brule\s+(\w+)', line)
                if m:
                    names.append(m.group(1))
    except Exception:
        pass
    return names


def _build_rule_classifications(rules_dir):
    """Build a mapping of rule_name -> classification by walking the rules tree.

    YARA-Rules: classified by parent directory name (parsed from file contents).
    Neo23x0: classified by case-insensitive rule name prefix.
    """
    classifications = {}
    if not os.path.isdir(rules_dir):
        return classifications

    for root, _dirs, files in os.walk(rules_dir):
        for f in files:
            if not f.endswith('.yar'):
                continue
            file_path = os.path.join(root, f)
            rel = os.path.relpath(root, rules_dir)
            parts = rel.split(os.sep)

            # Determine source: YARA-Rules or Neo23x0
            if YARA_RULES_SUBDIR in parts:
                # YARA-Rules: use parent directory under yara-rules/
                idx = parts.index(YARA_RULES_SUBDIR)
                if idx + 1 < len(parts):
                    parent_dir = parts[idx + 1]
                    conf = YARA_RULES_CONFIDENCE.get(parent_dir, 'informational')
                else:
                    conf = 'informational'
                for rule_name in _extract_rule_names_from_file(file_path):
                    classifications[rule_name] = conf
            elif NEO23X0_SUBDIR in parts:
                # Neo23x0: use prefix matching on each rule name in the file
                for rule_name in _extract_rule_names_from_file(file_path):
                    name_upper = rule_name.upper()
                    conf = 'informational'
                    for prefix, level in NEO23X0_CONFIDENCE:
                        if name_upper.startswith(prefix.upper()):
                            conf = level
                            break
                    classifications[rule_name] = conf

    return classifications


def setup_yara_rules(data_dir=None):
    """Ensure a YARA rules directory exists with both Neo23x0 and YARA-Rules.

    Priority:
    1. ~/ohmypcap-data/yara-rules/ (already downloaded)
    2. Baked-in rules in /usr/share/yara-rules (Docker)
    3. Download from GitHub if internet is available

    Returns the rules directory path or None if no rules are available.
    """
    if data_dir is None:
        data_dir = os.path.expanduser('~/ohmypcap-data')
    rules_dir = os.path.join(data_dir, 'yara-rules')
    neo_index = os.path.join(rules_dir, NEO23X0_INDEX)
    yara_index = os.path.join(rules_dir, YARA_RULES_SUBDIR, 'index.yar')

    # Already downloaded/cached with at least one index present
    if os.path.isfile(neo_index) or os.path.isfile(yara_index):
        return rules_dir

    # Baked-in rules (Docker image)
    if os.path.isdir(BAKED_IN_YARA_DIR):
        try:
            shutil.copytree(BAKED_IN_YARA_DIR, rules_dir, dirs_exist_ok=True)
            neo_index = os.path.join(rules_dir, NEO23X0_INDEX)
            yara_index = os.path.join(rules_dir, YARA_RULES_SUBDIR, 'index.yar')
            if os.path.isfile(neo_index) or os.path.isfile(yara_index):
                return rules_dir
            # Generate neo23x0 index if missing (e.g., older baked image)
            _generate_neo23x0_index(rules_dir)
            if os.path.isfile(neo_index) or os.path.isfile(yara_index):
                return rules_dir
        except Exception as e:
            print(f'Warning: could not copy baked-in YARA rules: {e}')

    # Try to download
    if _has_internet_access():
        print('Internet access detected — downloading YARA rules...')
        try:
            _download_neo23x0_rules(rules_dir)
            _clone_yara_rules(rules_dir)
            _generate_neo23x0_index(rules_dir)
            return rules_dir
        except Exception as e:
            print(f'Warning: could not download YARA rules: {e}')
    else:
        print('No internet access detected — YARA rules not available')

    return None


def _has_internet_access():
    try:
        import socket
        socket.create_connection(('github.com', 443), timeout=5)
        return True
    except OSError:
        return False


def _download_neo23x0_rules(rules_dir):
    """Download and extract Neo23x0 signature-base YARA rules."""
    neo_dir = os.path.join(rules_dir, NEO23X0_SUBDIR)
    os.makedirs(neo_dir, exist_ok=True)
    tmp_zip = os.path.join(rules_dir, 'neo23x0.zip')

    req = urllib.request.Request(NEO23X0_URL, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=60) as resp:
        with open(tmp_zip, 'wb') as f:
            f.write(resp.read())

    import zipfile
    with zipfile.ZipFile(tmp_zip, 'r') as zf:
        for member in zf.namelist():
            if member.startswith(NEO23X0_ZIP_SUBDIR) and member.endswith('.yar'):
                basename = os.path.basename(member)
                with zf.open(member) as src, open(os.path.join(neo_dir, basename), 'wb') as dst:
                    dst.write(src.read())

    os.unlink(tmp_zip)
    print('Neo23x0 YARA rules downloaded successfully')


def _clone_yara_rules(rules_dir):
    """Clone YARA-Rules repository."""
    yara_dir = os.path.join(rules_dir, YARA_RULES_SUBDIR)
    # Remove partial/empty directory if it exists
    if os.path.isdir(yara_dir) and not os.path.isdir(os.path.join(yara_dir, '.git')):
        shutil.rmtree(yara_dir)
    if not os.path.isdir(yara_dir):
        subprocess.run(
            ['git', 'clone', '--depth', '1', YARA_RULES_GIT_URL, yara_dir],
            capture_output=True, text=True, timeout=120, check=True
        )
    print('YARA-Rules downloaded successfully')


def _generate_neo23x0_index(rules_dir):
    """Generate neo23x0-index.yar that includes all Neo23x0 rule files."""
    lines = ['// Auto-generated Neo23x0 YARA rules index', '']
    neo_dir = os.path.join(rules_dir, NEO23X0_SUBDIR)
    if os.path.isdir(neo_dir):
        for f in sorted(os.listdir(neo_dir)):
            if f.endswith('.yar'):
                lines.append(f'include "{NEO23X0_SUBDIR}/{f}"')
        lines.append('')

    index_path = os.path.join(rules_dir, NEO23X0_INDEX)
    with open(index_path, 'w') as f:
        f.write('\n'.join(lines))
    print(f'Generated {NEO23X0_INDEX} with {len(lines)} lines')


def _run_yara_with_index(index_path, list_path, filestore_dir=None):
    """Run YARA against a single index file and return parsed matches."""
    if not os.path.isfile(index_path):
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
                '--scan-list', index_path, list_path
            ],
            capture_output=True, text=True, timeout=300
        )
    except subprocess.TimeoutExpired:
        print(f'YARA scan timed out for {os.path.basename(index_path)}')
        return []
    except Exception as e:
        print(f'YARA scan error for {os.path.basename(index_path)}: {e}')
        return []

    return _parse_yara_output(result.stdout, filestore_dir)


def run_yara_scan(filestore_dir, rules_dir):
    """Run YARA on extracted files and return list of matches.

    Each match is a dict:
        {
            'rule_name': str,
            'sha256': str,
            'file_path': str,
            'tags': list[str],
            'meta': dict,
            'confidence': str,
        }
    """
    if not os.path.isdir(filestore_dir):
        return []

    # Build rule classification mapping before scanning
    rule_classifications = _build_rule_classifications(rules_dir)

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
        # Run each ruleset independently to avoid duplicate identifier conflicts
        all_matches = []
        seen = set()

        neo_index = os.path.join(rules_dir, NEO23X0_INDEX)
        yara_index = os.path.join(rules_dir, YARA_RULES_SUBDIR, 'index.yar')

        for index_path in (neo_index, yara_index):
            matches = _run_yara_with_index(index_path, list_path, filestore_dir)
            for m in matches:
                key = (m['rule_name'], m['sha256'])
                if key not in seen:
                    seen.add(key)
                    m['confidence'] = rule_classifications.get(m['rule_name'], 'informational')
                    all_matches.append(m)

        return all_matches
    finally:
        try:
            os.unlink(list_path)
        except Exception:
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
        if filestore_dir and not file_path.startswith(filestore_dir):
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
        except Exception:
            pass
    return ''


def write_yara_matches_json(dir_path, matches):
    """Write YARA match results to yara_matches.json in the analysis directory."""
    out_path = os.path.join(dir_path, 'yara_matches.json')
    with open(out_path, 'w') as f:
        json.dump(matches, f)


def run_yara_pipeline(dir_path, data_dir=None):
    """Full YARA pipeline: setup rules, scan filestore, write results.

    Returns True if scanning completed (even with zero matches).
    Returns False if YARA is unavailable or rules could not be obtained.
    """
    if not check_yara_executable():
        return False

    if data_dir is None:
        data_dir = os.path.expanduser('~/ohmypcap-data')
    rules_dir = os.path.join(data_dir, 'yara-rules')
    if not os.path.isdir(rules_dir):
        return False

    filestore_dir = os.path.join(dir_path, 'filestore')
    if not os.path.isdir(filestore_dir):
        return False

    matches = run_yara_scan(filestore_dir, rules_dir)
    write_yara_matches_json(dir_path, matches)
    return True


def scan_single_file(file_path, rules_dir):
    """Run YARA on a single arbitrary file and return match results with hashes.

    Returns a tuple: (matches, sha256, md5, sha1)
        matches: list of dicts (same format as run_yara_scan)
        sha256: str
        md5: str
        sha1: str
    """
    import hashlib

    if not os.path.isfile(file_path):
        return [], '', '', ''

    # Compute hashes
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)

    file_sha256 = sha256.hexdigest()
    file_md5 = md5.hexdigest()
    file_sha1 = sha1.hexdigest()

    rule_classifications = _build_rule_classifications(rules_dir)

    # Write file list for --scan-list
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as list_file:
        list_file.write(file_path + '\n')
        list_path = list_file.name

    try:
        all_matches = []
        seen = set()

        neo_index = os.path.join(rules_dir, NEO23X0_INDEX)
        yara_index = os.path.join(rules_dir, YARA_RULES_SUBDIR, 'index.yar')

        for index_path in (neo_index, yara_index):
            matches = _run_yara_with_index(index_path, list_path)
            for m in matches:
                key = (m['rule_name'], file_sha256)
                if key not in seen:
                    seen.add(key)
                    m['sha256'] = file_sha256
                    m['confidence'] = rule_classifications.get(m['rule_name'], 'informational')
                    all_matches.append(m)

        return all_matches, file_sha256, file_md5, file_sha1
    finally:
        try:
            os.unlink(list_path)
        except Exception:
            pass
