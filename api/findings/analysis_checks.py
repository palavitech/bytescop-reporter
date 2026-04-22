"""Analysis check registry — defines placeholder findings for malware analysis.

Each entry describes a check that can be seeded as a placeholder finding and
executed on demand.  Adding a new check = adding one dict to ANALYSIS_CHECKS.

file_types
----------
Controls which samples get this check seeded.  Empty list = universal (any
file).  Non-empty list = seed only when the sample's detected tags intersect.

    []          → hash_identification, extract_strings, etc.
    ['pe']      → PE-specific checks
    ['office']  → future Office document checks
"""
import logging

logger = logging.getLogger(__name__)

ANALYSIS_CHECKS = [
    {
        'key': 'hash_identification',
        'title': 'File Hash Identification',
        'description_placeholder': '*Pending execution.* Click **Execute** to generate file hashes.',
        'analysis_type': 'static',
        'file_types': [],
    },
    {
        'key': 'extract_strings',
        'title': 'Extract Strings',
        'description_placeholder': '*Pending execution.* Click **Execute** to extract printable strings.',
        'analysis_type': 'static',
        'file_types': [],
    },
    {
        'key': 'special_strings',
        'title': 'Special Strings',
        'description_placeholder': '*Pending execution.* Click **Execute** to identify email addresses, phone numbers, IP addresses, and URLs.',
        'analysis_type': 'static',
        'file_types': [],
    },
    {
        'key': 'file_type',
        'title': 'File Type',
        'description_placeholder': '*Pending execution.* Click **Execute** to identify file type, MIME type, and format details.',
        'analysis_type': 'static',
        'file_types': [],
    },
    {
        'key': 'pe_headers',
        'title': 'PE Headers',
        'description_placeholder': '*Pending execution.* Click **Execute** to parse PE headers (machine type, compile timestamp, entry point, subsystem).',
        'analysis_type': 'static',
        'file_types': ['pe'],
    },
    {
        'key': 'pe_imports',
        'title': 'PE Imports & Suspicious APIs',
        'description_placeholder': '*Pending execution.* Click **Execute** to list imported DLLs/functions and flag suspicious API calls.',
        'analysis_type': 'static',
        'file_types': ['pe'],
    },
    {
        'key': 'pe_exports',
        'title': 'PE Exports',
        'description_placeholder': '*Pending execution.* Click **Execute** to list exported functions.',
        'analysis_type': 'static',
        'file_types': ['pe'],
    },
    {
        'key': 'pe_packer_detection',
        'title': 'Packer Detection',
        'description_placeholder': '*Pending execution.* Click **Execute** to check for packing, high entropy, and known packer signatures.',
        'analysis_type': 'static',
        'file_types': ['pe'],
    },
    {
        'key': 'pe_resources',
        'title': 'PE Resources & Version Info',
        'description_placeholder': '*Pending execution.* Click **Execute** to extract embedded resources, version strings, PDB paths, and manifest info.',
        'analysis_type': 'static',
        'file_types': ['pe'],
    },
    {
        'key': 'compile_time',
        'title': 'Compile Time',
        'description_placeholder': '*Pending execution.* Click **Execute** to extract and analyse the PE compile timestamp for anomalies or timestomping.',
        'analysis_type': 'static',
        'file_types': ['pe'],
    },
]

# Keyed lookup for fast access by check key.
ANALYSIS_CHECKS_BY_KEY = {c['key']: c for c in ANALYSIS_CHECKS}


# ---------------------------------------------------------------------------
# Lightweight file-type detection via magic bytes
# ---------------------------------------------------------------------------

# Magic byte signatures → tag.  Checked in order; first match wins.
_MAGIC_TABLE = [
    (b'MZ',             'pe'),      # DOS/PE executable
    # Future: Office, ELF, Mach-O, etc.
    # (b'\xd0\xcf\x11\xe0', 'office'),  # OLE2 Compound (legacy .doc/.xls)
    # (b'PK',              'office'),  # OOXML (.docx/.xlsx) — needs extra check
    # (b'\x7fELF',         'elf'),
]


def detect_sample_tags(storage, sample) -> frozenset:
    """Read the first bytes of a sample and return file-type tags.

    Returns a frozenset of strings, e.g. frozenset({'pe'}).
    Returns empty frozenset if the file type is unrecognised or unreadable.
    """
    try:
        f = storage.open(sample.storage_uri)
        try:
            header = f.read(8)
        finally:
            f.close()
    except Exception:
        logger.warning('Cannot read sample for type detection: %s', sample.pk)
        return frozenset()

    tags = set()
    for magic, tag in _MAGIC_TABLE:
        if header[:len(magic)] == magic:
            tags.add(tag)
    return frozenset(tags)
