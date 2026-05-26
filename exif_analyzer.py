#!/usr/bin/env python3
"""ExifTool-based metadata extraction for OhMyPCAP.

Provides rich format-specific metadata for PE executables, PDFs, images,
and Office documents. Runs selectively based on MIME type and only for
files where our lightweight analyzer alone doesn't tell the full story.
"""

import json
import os
import subprocess

import config

# MIME type patterns that warrant ExifTool analysis
EXIFTOOL_MIME_PATTERNS = (
    'application/x-dosexec',
    'application/vnd.microsoft.portable-executable',
    'application/pdf',
    'image/',
    'application/vnd.ms-',
    'application/vnd.openxmlformats',
    'application/msword',
    'application/rtf',
    'application/x-ole-storage',
)

# Whitelisted fields per file type category
# Keys are ExifTool tag names; values are human-friendly display names
EXIF_FIELD_MAP = {
    'pe': {
        'TimeStamp': 'Compilation Timestamp',
        'PEType': 'PE Type',
        'MachineType': 'Machine Type',
        'ImageFileCharacteristics': 'Characteristics',
        'ImageVersion': 'Image Version',
        'OSVersion': 'OS Version',
        'Subsystem': 'Subsystem',
        'SubsystemVersion': 'Subsystem Version',
        'EntryPoint': 'Entry Point',
        'ImageSize': 'Image Size',
        'InitializedDataSize': 'Initialized Data Size',
        'UninitializedDataSize': 'Uninitialized Data Size',
        'CompanyName': 'Company Name',
        'FileDescription': 'File Description',
        'FileVersion': 'File Version',
        'InternalName': 'Internal Name',
        'LegalCopyright': 'Legal Copyright',
        'OriginalFilename': 'Original Filename',
        'ProductName': 'Product Name',
        'ProductVersion': 'Product Version',
        'LanguageCode': 'Language Code',
        'CharacterSet': 'Character Set',
        'Signed': 'Signed',
    },
    'pdf': {
        'PDFVersion': 'PDF Version',
        'Creator': 'Creator',
        'Producer': 'Producer',
        'Author': 'Author',
        'Title': 'Title',
        'Subject': 'Subject',
        'Keywords': 'Keywords',
        'CreateDate': 'Create Date',
        'ModifyDate': 'Modify Date',
        'PageCount': 'Page Count',
        'Encryption': 'Encryption',
        'Linearized': 'Linearized',
    },
    'image': {
        'Make': 'Make',
        'Model': 'Model',
        'Software': 'Software',
        'DateTimeOriginal': 'Date Time Original',
        'GPSLatitude': 'GPS Latitude',
        'GPSLongitude': 'GPS Longitude',
        'GPSAltitude': 'GPS Altitude',
        'ImageWidth': 'Image Width',
        'ImageHeight': 'Image Height',
        'XResolution': 'X Resolution',
        'YResolution': 'Y Resolution',
        'ResolutionUnit': 'Resolution Unit',
        'Compression': 'Compression',
        'ColorSpace': 'Color Space',
    },
    'office': {
        'Author': 'Author',
        'Company': 'Company',
        'Template': 'Template',
        'CreateDate': 'Create Date',
        'ModifyDate': 'Modify Date',
        'LastModifiedBy': 'Last Modified By',
        'Application': 'Application',
        'AppVersion': 'App Version',
        'TotalEditTime': 'Total Edit Time',
        'RevisionNumber': 'Revision Number',
        'Pages': 'Pages',
        'Words': 'Words',
        'Characters': 'Characters',
    },
}

# Tags whose values should be redacted in the UI
REDACTED_TAGS = {'GPSLatitude', 'GPSLongitude', 'GPSAltitude'}


def _should_run_exiftool(mime_type):
    """Return True if the MIME type warrants ExifTool analysis."""
    if not mime_type:
        return False
    mime_lower = mime_type.lower()
    return any(mime_lower.startswith(p) or mime_lower == p for p in EXIFTOOL_MIME_PATTERNS)


def _determine_category(mime_type, file_type):
    """Determine the file category for field whitelisting."""
    if not mime_type:
        return None
    mime_lower = mime_type.lower()
    file_lower = file_type.lower()
    # PE executables
    if (mime_lower in ('application/x-dosexec', 'application/vnd.microsoft.portable-executable')
            or 'pe' in file_lower or 'exe' in file_lower or 'win32' in file_lower
            or 'win64' in file_lower or 'executable' in file_lower):
        return 'pe'
    if mime_lower == 'application/pdf' or 'pdf' in file_lower:
        return 'pdf'
    if mime_lower.startswith('image/'):
        return 'image'
    if (mime_lower.startswith('application/vnd.ms-')
            or mime_lower.startswith('application/vnd.openxmlformats')
            or mime_lower in ('application/msword', 'application/rtf', 'application/x-ole-storage')):
        return 'office'
    return None


def extract_exif(file_path, mime_type=''):
    """Run ExifTool on a file and return a curated metadata dict.

    Args:
        file_path: Path to the file to analyze.
        mime_type: Optional MIME type hint to skip ExifTool for unsupported types.

    Returns:
        Dict of display_name -> value for whitelisted fields, or {} if ExifTool
        is unavailable, times out, or the file type isn't supported.
    """
    if not _should_run_exiftool(mime_type):
        return {}

    try:
        result = subprocess.run(
            ['exiftool', '-j', file_path],
            capture_output=True, text=True, timeout=3
        )
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired) as e:
        print(f'Warning: ExifTool failed for {file_path}: {e}')
        return {}

    if result.returncode != 0:
        return {}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}

    if not data or not isinstance(data, list):
        return {}

    tags = data[0]
    file_type = tags.get('FileType', '')
    category = _determine_category(mime_type, file_type)
    if not category:
        return {}

    field_map = EXIF_FIELD_MAP.get(category, {})
    extracted = {}
    for tag, display_name in field_map.items():
        value = tags.get(tag)
        if value is not None and str(value).strip():
            if tag in REDACTED_TAGS:
                extracted[display_name] = 'REDACTED'
            else:
                extracted[display_name] = str(value).strip()

    return extracted
