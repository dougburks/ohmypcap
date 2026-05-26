#!/usr/bin/env python3
"""Lightweight file metadata extraction for OhMyPCAP.

Provides file type detection (via the `file` command), Shannon entropy
calculation, and printable string extraction. Used to enrich fileinfo events
when YARA produces no matches.
"""

import math
import os
import re
import subprocess

import config
from exif_analyzer import extract_exif


def shannon_entropy(data):
    """Calculate Shannon entropy of byte data (0.0–8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        freq = count / length
        entropy -= freq * math.log2(freq)
    return round(entropy, 2)


def extract_strings(file_path, min_len=4, max_count=50, max_len=100):
    """Extract printable ASCII strings from a file.

    Returns a list of up to `max_count` strings, each truncated to `max_len`.
    """
    strings = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read(config.MAX_STRINGS_READ_SIZE)  # cap for speed
    except OSError:
        return strings

    # Find sequences of printable ASCII characters
    for match in re.finditer(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', data):
        s = match.group().decode('ascii', errors='ignore')
        if s:
            strings.append(s[:max_len])
        if len(strings) >= max_count:
            break
    return strings


def analyze_file(file_path):
    """Analyze a file and return a metadata dict.

    Fields:
        file_type: Human-readable description from `file -b`
        mime_type: MIME type from `file -b --mime-type`
        entropy: Shannon entropy (0.0–8.0)
        strings: List of top printable ASCII strings
    """
    metadata = {
        'file_type': '',
        'mime_type': '',
        'entropy': 0.0,
        'strings': [],
    }

    if not os.path.isfile(file_path):
        return metadata

    # file command for type and MIME
    try:
        result = subprocess.run(
            ['file', '--brief', file_path],
            capture_output=True, text=True, timeout=config.FILE_COMMAND_TIMEOUT
        )
        if result.returncode == 0:
            metadata['file_type'] = result.stdout.strip()
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        pass

    try:
        result = subprocess.run(
            ['file', '--brief', '--mime-type', file_path],
            capture_output=True, text=True, timeout=config.FILE_COMMAND_TIMEOUT
        )
        if result.returncode == 0:
            metadata['mime_type'] = result.stdout.strip()
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        pass

    # entropy and strings
    try:
        with open(file_path, 'rb') as f:
            data = f.read(config.MAX_ENTROPY_READ_SIZE)  # cap for entropy
        metadata['entropy'] = shannon_entropy(data)
        metadata['strings'] = extract_strings(file_path)
    except OSError:
        pass

    # rich format-specific metadata via ExifTool
    exif_data = extract_exif(file_path, metadata.get('mime_type', ''))
    if exif_data:
        metadata['exif'] = exif_data

    return metadata
