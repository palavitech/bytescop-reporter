"""Per-check executor functions for malware analysis findings.

Each executor takes (storage, sample, finding) and returns the populated
description_md string.  They are pure functions — side-effect free except
for reading sample bytes from storage.
"""

import hashlib
import mimetypes
import re

try:
    import magic as _magic
    _HAS_MAGIC = True
except ImportError:
    _HAS_MAGIC = False

# Match printable ASCII runs of 6+ chars in raw bytes.
_STRINGS_RE = re.compile(rb'[\x20-\x7e]{6,}')

MAX_STRINGS = 500
MAX_STRING_LENGTH = 200


def execute_hash_identification(storage, sample, finding):
    """Compute MD5, SHA-1, SHA-256 hashes of the sample file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    f = storage.open(sample.storage_uri)
    try:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    finally:
        f.close()

    filename = sample.original_filename
    return (
        f'## File Hashes — {filename}\n\n'
        f'| Algorithm | Hash |\n'
        f'|-----------|------|\n'
        f'| MD5 | `{md5.hexdigest()}` |\n'
        f'| SHA-1 | `{sha1.hexdigest()}` |\n'
        f'| SHA-256 | `{sha256.hexdigest()}` |\n'
    )


def execute_extract_strings(storage, sample, finding):
    """Extract printable ASCII strings (> 6 chars) from the sample file."""
    f = storage.open(sample.storage_uri)
    try:
        data = f.read()
    finally:
        f.close()

    matches = _STRINGS_RE.findall(data)
    strings = [m.decode('ascii', errors='replace') for m in matches]
    filename = sample.original_filename

    if strings:
        truncated = len(strings) > MAX_STRINGS
        display_strings = strings[:MAX_STRINGS]
        lines = '\n'.join(s[:MAX_STRING_LENGTH] for s in display_strings)
        description = (
            f'## Extracted Strings — {filename}\n\n'
            f'Found **{len(strings)}** printable strings (> 6 characters).'
        )
        if truncated:
            description += f' Showing first {MAX_STRINGS}.'
        description += f'\n\n```\n{lines}\n```\n'
    else:
        description = (
            f'## Extracted Strings — {filename}\n\n'
            f'No printable strings longer than 4 characters were found.'
        )

    return description


_EMAIL_RE = re.compile(rb'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_PHONE_RE = re.compile(rb'(?:\+?\d{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}')
_IPV4_RE = re.compile(rb'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_URL_RE = re.compile(rb'https?://[^\s\x00-\x1f"\'<>\x7f]{4,}')

MAX_SPECIAL = 200


def execute_special_strings(storage, sample, finding):
    """Identify email addresses, phone numbers, IP addresses, and URLs."""
    f = storage.open(sample.storage_uri)
    try:
        data = f.read()
    finally:
        f.close()

    filename = sample.original_filename

    categories = [
        ('Email Addresses', _EMAIL_RE),
        ('IP Addresses', _IPV4_RE),
        ('URLs', _URL_RE),
        ('Phone Numbers', _PHONE_RE),
    ]

    sections = []
    grand_total = 0

    for label, pattern in categories:
        raw_matches = pattern.findall(data)
        decoded = sorted({m.decode('ascii', errors='replace') for m in raw_matches})
        grand_total += len(decoded)

        if not decoded:
            sections.append(f'### {label}\n\nNone found.\n')
            continue

        truncated = len(decoded) > MAX_SPECIAL
        display = decoded[:MAX_SPECIAL]
        lines = '\n'.join(display)
        section = f'### {label}\n\nFound **{len(decoded)}** unique match{"es" if len(decoded) != 1 else ""}.'
        if truncated:
            section += f' Showing first {MAX_SPECIAL}.'
        section += f'\n\n```\n{lines}\n```\n'
        sections.append(section)

    description = (
        f'## Special Strings — {filename}\n\n'
        f'Scanned for email addresses, phone numbers, IP addresses, and URLs. '
        f'**{grand_total}** total unique matches.\n\n'
    )
    description += '\n'.join(sections)
    return description


def _format_size(size_bytes):
    """Human-readable file size."""
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size_bytes < 1024:
            return f'{size_bytes:.2f} {unit}' if unit != 'B' else f'{size_bytes} {unit}'
        size_bytes /= 1024
    return f'{size_bytes:.2f} TB'


def execute_file_type(storage, sample, finding):
    """Identify file type, MIME type, and format description (like the `file` command)."""
    f = storage.open(sample.storage_uri)
    try:
        header = f.read(8192)
        f.seek(0, 2)
        file_size = f.tell()
    finally:
        f.close()

    filename = sample.original_filename

    if _HAS_MAGIC:
        description = _magic.from_buffer(header)
        mime_type = _magic.from_buffer(header, mime=True)
    else:
        mime_type, _ = mimetypes.guess_type(filename)
        mime_type = mime_type or 'application/octet-stream'
        description = 'Install python-magic for detailed file type detection'

    return (
        f'## File Type — {filename}\n\n'
        f'| Property | Value |\n'
        f'|----------|-------|\n'
        f'| MIME Type | `{mime_type}` |\n'
        f'| Description | {description} |\n'
        f'| File Size | {_format_size(file_size)} |\n'
    )


from .pe_executors import (
    execute_pe_headers,
    execute_pe_imports,
    execute_pe_exports,
    execute_pe_packer_detection,
    execute_pe_resources,
    execute_compile_time,
)

# Registry mapping check key → executor function.
EXECUTORS = {
    'hash_identification': execute_hash_identification,
    'extract_strings': execute_extract_strings,
    'special_strings': execute_special_strings,
    'file_type': execute_file_type,
    'pe_headers': execute_pe_headers,
    'pe_imports': execute_pe_imports,
    'pe_exports': execute_pe_exports,
    'pe_packer_detection': execute_pe_packer_detection,
    'pe_resources': execute_pe_resources,
    'compile_time': execute_compile_time,
}
