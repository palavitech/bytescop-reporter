"""PE-specific executor functions for malware analysis findings.

Each executor takes (storage, sample, finding) and returns a Markdown
description string.  All functions rely on the ``pefile`` library.
If the sample is not a valid PE, the executor returns a clear message
rather than raising.
"""

import math
from collections import defaultdict
from datetime import datetime, timezone

try:
    import pefile
    _HAS_PEFILE = True
except ImportError:
    _HAS_PEFILE = False


def _read_sample(storage, sample):
    """Read full sample bytes from storage."""
    f = storage.open(sample.storage_uri)
    try:
        return f.read()
    finally:
        f.close()


def _parse_pe(data):
    """Attempt to parse PE.  Returns (pe, error_msg)."""
    if not _HAS_PEFILE:
        return None, 'pefile library is not installed. Run `pip install pefile`.'
    try:
        pe = pefile.PE(data=data)
        return pe, None
    except pefile.PEFormatError:
        return None, 'File is not a valid PE executable.'


def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0.0 – 8.0)."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ---------------------------------------------------------------------------
# Suspicious API lookup table
# ---------------------------------------------------------------------------

SUSPICIOUS_APIS: dict[str, tuple[str, str]] = {
    # Process Injection
    'CreateRemoteThread': ('Process Injection', 'Creates a thread in another process'),
    'NtCreateThreadEx': ('Process Injection', 'Low-level remote thread creation'),
    'RtlCreateUserThread': ('Process Injection', 'Undocumented remote thread creation'),
    'VirtualAllocEx': ('Process Injection', 'Allocates memory in another process'),
    'WriteProcessMemory': ('Process Injection', 'Writes to another process memory'),
    'OpenProcess': ('Process Injection', 'Opens handle to another process'),
    'QueueUserAPC': ('Process Injection', 'Queues APC to a thread (APC injection)'),
    'NtUnmapViewOfSection': ('Process Injection', 'Unmaps section (process hollowing)'),
    'SetThreadContext': ('Process Injection', 'Modifies thread context (process hollowing)'),
    'ResumeThread': ('Process Injection', 'Resumes suspended thread after injection'),

    # Code Execution
    'WinExec': ('Code Execution', 'Executes a command'),
    'ShellExecuteA': ('Code Execution', 'Launches program or opens file'),
    'ShellExecuteW': ('Code Execution', 'Launches program or opens file'),
    'ShellExecuteExA': ('Code Execution', 'Extended shell execution'),
    'ShellExecuteExW': ('Code Execution', 'Extended shell execution'),
    'CreateProcessA': ('Code Execution', 'Creates a new process'),
    'CreateProcessW': ('Code Execution', 'Creates a new process'),
    'CreateProcessInternalW': ('Code Execution', 'Internal process creation'),
    'system': ('Code Execution', 'C runtime command execution'),

    # Keylogging / Input Capture
    'SetWindowsHookExA': ('Keylogging', 'Installs a hook (keylogger, mouse)'),
    'SetWindowsHookExW': ('Keylogging', 'Installs a hook (keylogger, mouse)'),
    'GetAsyncKeyState': ('Keylogging', 'Checks key state asynchronously'),
    'GetKeyState': ('Keylogging', 'Checks key state'),
    'GetKeyboardState': ('Keylogging', 'Reads full keyboard state'),
    'GetClipboardData': ('Keylogging', 'Reads clipboard contents'),

    # Anti-Debug / Evasion
    'IsDebuggerPresent': ('Anti-Debug', 'Checks if a debugger is attached'),
    'CheckRemoteDebuggerPresent': ('Anti-Debug', 'Checks for remote debugger'),
    'NtQueryInformationProcess': ('Anti-Debug', 'Queries process info (debug detection)'),
    'OutputDebugStringA': ('Anti-Debug', 'Anti-debug technique via debug output'),
    'OutputDebugStringW': ('Anti-Debug', 'Anti-debug technique via debug output'),
    'GetTickCount': ('Anti-Debug', 'Timing check (sandbox/debug detection)'),
    'QueryPerformanceCounter': ('Anti-Debug', 'High-res timing check (sandbox detection)'),
    'NtQuerySystemInformation': ('Anti-Debug', 'System info query (VM/sandbox detection)'),

    # Persistence
    'RegSetValueExA': ('Persistence', 'Sets registry value (autorun, config)'),
    'RegSetValueExW': ('Persistence', 'Sets registry value (autorun, config)'),
    'RegCreateKeyExA': ('Persistence', 'Creates registry key'),
    'RegCreateKeyExW': ('Persistence', 'Creates registry key'),
    'CreateServiceA': ('Persistence', 'Creates a Windows service'),
    'CreateServiceW': ('Persistence', 'Creates a Windows service'),
    'StartServiceA': ('Persistence', 'Starts a Windows service'),
    'StartServiceW': ('Persistence', 'Starts a Windows service'),

    # Network
    'InternetOpenA': ('Network', 'Initialises WinINet (HTTP communication)'),
    'InternetOpenW': ('Network', 'Initialises WinINet (HTTP communication)'),
    'InternetOpenUrlA': ('Network', 'Opens a URL'),
    'InternetOpenUrlW': ('Network', 'Opens a URL'),
    'InternetConnectA': ('Network', 'Connects to server'),
    'InternetConnectW': ('Network', 'Connects to server'),
    'HttpOpenRequestA': ('Network', 'Creates an HTTP request handle'),
    'HttpOpenRequestW': ('Network', 'Creates an HTTP request handle'),
    'HttpSendRequestA': ('Network', 'Sends HTTP request'),
    'HttpSendRequestW': ('Network', 'Sends HTTP request'),
    'URLDownloadToFileA': ('Network', 'Downloads file from URL'),
    'URLDownloadToFileW': ('Network', 'Downloads file from URL'),
    'URLDownloadToCacheFileA': ('Network', 'Downloads file to cache'),
    'WSAStartup': ('Network', 'Initialises Winsock'),
    'connect': ('Network', 'Connects to remote socket'),
    'send': ('Network', 'Sends data over socket'),
    'recv': ('Network', 'Receives data from socket'),
    'InternetReadFile': ('Network', 'Reads data from internet handle'),

    # Crypto
    'CryptEncrypt': ('Crypto', 'Encrypts data (ransomware indicator)'),
    'CryptDecrypt': ('Crypto', 'Decrypts data'),
    'CryptAcquireContextA': ('Crypto', 'Acquires crypto provider handle'),
    'CryptAcquireContextW': ('Crypto', 'Acquires crypto provider handle'),
    'CryptCreateHash': ('Crypto', 'Creates a hash object'),
    'CryptHashData': ('Crypto', 'Hashes data'),
    'CryptDeriveKey': ('Crypto', 'Derives encryption key'),
    'CryptGenKey': ('Crypto', 'Generates encryption key'),
    'BCryptEncrypt': ('Crypto', 'Next-gen crypto encryption'),
    'BCryptDecrypt': ('Crypto', 'Next-gen crypto decryption'),

    # Privilege Escalation
    'AdjustTokenPrivileges': ('Privilege Escalation', 'Adjusts process token privileges'),
    'OpenProcessToken': ('Privilege Escalation', 'Opens process token'),
    'LookupPrivilegeValueA': ('Privilege Escalation', 'Looks up privilege LUID'),
    'LookupPrivilegeValueW': ('Privilege Escalation', 'Looks up privilege LUID'),

    # DLL Injection / Loading
    'LoadLibraryA': ('DLL Loading', 'Loads DLL at runtime'),
    'LoadLibraryW': ('DLL Loading', 'Loads DLL at runtime'),
    'LoadLibraryExA': ('DLL Loading', 'Loads DLL with extended options'),
    'LoadLibraryExW': ('DLL Loading', 'Loads DLL with extended options'),
    'GetProcAddress': ('DLL Loading', 'Resolves function address dynamically'),
    'LdrLoadDll': ('DLL Loading', 'Low-level DLL loading'),

    # File Operations
    'DeleteFileA': ('File Operations', 'Deletes a file'),
    'DeleteFileW': ('File Operations', 'Deletes a file'),
    'MoveFileA': ('File Operations', 'Moves/renames a file'),
    'MoveFileW': ('File Operations', 'Moves/renames a file'),
    'CopyFileA': ('File Operations', 'Copies a file'),
    'CopyFileW': ('File Operations', 'Copies a file'),
}

# Known packer section names and signatures
KNOWN_PACKER_SECTIONS = {
    'UPX0': 'UPX', 'UPX1': 'UPX', 'UPX2': 'UPX',
    '.aspack': 'ASPack', '.adata': 'ASPack',
    '.nsp0': 'NsPack', '.nsp1': 'NsPack', '.nsp2': 'NsPack',
    '.Themida': 'Themida', '.Winlice': 'Themida',
    '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect',
    '.petite': 'Petite',
    '.MPress1': 'MPress', '.MPress2': 'MPress',
    'MEW': 'MEW',
    '.MPRESS1': 'MPress', '.MPRESS2': 'MPress',
    '.perplex': 'Perplex',
    '.packed': 'Generic Packer',
    '.enigma1': 'Enigma Protector', '.enigma2': 'Enigma Protector',
    'PEC2TO': 'PECompact', 'PEC2MO': 'PECompact', 'PECompact2': 'PECompact',
    '.RLPack': 'RLPack',
    '.shrink1': 'Shrinker', '.shrink2': 'Shrinker', '.shrink3': 'Shrinker',
}

# Known packer entry-point byte signatures.
# Each tuple: (name, pattern) where pattern is a tuple of int|None (None = wildcard).
KNOWN_PACKER_EP_SIGNATURES = [
    ('FSG 1.0', (0xBB, None, None, None, 0x00, 0xBF, None, None, None, 0x00, 0xBE)),
    ('FSG 1.3', (0xBE, None, None, None, 0x00, 0xAD, 0x93, 0xAD)),
    ('FSG 2.0', (0x87, 0x25, None, None, None, None, 0x61, 0x94)),
]


def _match_ep_signatures(pe, data):
    """Match entry-point bytes against known packer signatures.  Returns set of packer names."""
    try:
        ep_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    except Exception:
        return set()
    ep_bytes = data[ep_offset:ep_offset + 64]
    matched = set()
    for name, pattern in KNOWN_PACKER_EP_SIGNATURES:
        if len(ep_bytes) >= len(pattern) and all(
            p is None or ep_bytes[i] == p for i, p in enumerate(pattern)
        ):
            matched.add(name)
    return matched


# ---------------------------------------------------------------------------
# PE Header executor
# ---------------------------------------------------------------------------

MACHINE_TYPES = {
    0x14c: 'x86 (i386)',
    0x8664: 'x64 (AMD64)',
    0x1c0: 'ARM',
    0xaa64: 'ARM64',
    0x200: 'IA64 (Itanium)',
}

SUBSYSTEM_NAMES = {
    0: 'Unknown',
    1: 'Native',
    2: 'Windows GUI',
    3: 'Windows Console',
    5: 'OS/2 Console',
    7: 'POSIX Console',
    9: 'Windows CE GUI',
    10: 'EFI Application',
    11: 'EFI Boot Service Driver',
    12: 'EFI Runtime Driver',
    13: 'EFI ROM',
    14: 'Xbox',
    16: 'Windows Boot Application',
}


def execute_pe_headers(storage, sample, finding):
    """Parse PE DOS/NT headers, machine type, compile timestamp, entry point, subsystem."""
    data = _read_sample(storage, sample)
    pe, err = _parse_pe(data)
    if err:
        return f'## PE Headers — {sample.original_filename}\n\n{err}'

    filename = sample.original_filename
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    machine = MACHINE_TYPES.get(fh.Machine, f'0x{fh.Machine:04X}')
    timestamp_val = fh.TimeDateStamp
    try:
        compile_time = datetime.fromtimestamp(timestamp_val, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OSError, ValueError):
        compile_time = f'Invalid (0x{timestamp_val:08X})'

    subsystem = SUBSYSTEM_NAMES.get(oh.Subsystem, f'0x{oh.Subsystem:04X}')

    characteristics = []
    if fh.Characteristics & 0x0002:
        characteristics.append('EXECUTABLE_IMAGE')
    if fh.Characteristics & 0x0020:
        characteristics.append('LARGE_ADDRESS_AWARE')
    if fh.Characteristics & 0x2000:
        characteristics.append('DLL')
    if fh.Characteristics & 0x0100:
        characteristics.append('32BIT_MACHINE')

    dll_chars = []
    dll_char_val = oh.DllCharacteristics
    if dll_char_val & 0x0040:
        dll_chars.append('DYNAMIC_BASE (ASLR)')
    if dll_char_val & 0x0100:
        dll_chars.append('NX_COMPAT (DEP)')
    if dll_char_val & 0x4000:
        dll_chars.append('GUARD_CF')
    if dll_char_val & 0x0400:
        dll_chars.append('NO_SEH')
    if dll_char_val & 0x0800:
        dll_chars.append('NO_BIND')
    if dll_char_val & 0x8000:
        dll_chars.append('TERMINAL_SERVER_AWARE')
    if not (dll_char_val & 0x0040):
        dll_chars.append('**NO ASLR** (suspicious)')
    if not (dll_char_val & 0x0100):
        dll_chars.append('**NO DEP** (suspicious)')

    is_64 = fh.Machine == 0x8664
    pe_format = 'PE32+' if is_64 else 'PE32'

    md = (
        f'## PE Headers — {filename}\n\n'
        f'| Property | Value |\n'
        f'|----------|-------|\n'
        f'| Format | {pe_format} |\n'
        f'| Machine | {machine} |\n'
        f'| Compile Time | {compile_time} |\n'
        f'| Entry Point | `0x{oh.AddressOfEntryPoint:08X}` |\n'
        f'| Image Base | `0x{oh.ImageBase:016X}`{"" if is_64 else ""} |\n'
        f'| Subsystem | {subsystem} |\n'
        f'| Sections | {fh.NumberOfSections} |\n'
        f'| Characteristics | {", ".join(characteristics) or "None"} |\n'
        f'| DLL Characteristics | {", ".join(dll_chars) or "None"} |\n'
    )

    pe.close()
    return md


# ---------------------------------------------------------------------------
# PE Imports & Suspicious APIs executor
# ---------------------------------------------------------------------------

def execute_pe_imports(storage, sample, finding):
    """List imported DLLs/functions and flag suspicious API calls."""
    data = _read_sample(storage, sample)
    pe, err = _parse_pe(data)
    if err:
        return f'## PE Imports — {sample.original_filename}\n\n{err}'

    filename = sample.original_filename

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        pe.close()
        return f'## PE Imports — {filename}\n\nNo import table found (possibly packed or corrupted).\n'

    # Collect all imports
    all_imports: dict[str, list[str]] = {}
    flagged: dict[str, list[tuple[str, str, str]]] = defaultdict(list)  # category → [(dll, func, desc)]

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8', errors='replace')
        funcs = []
        for imp in entry.imports:
            func_name = imp.name.decode('utf-8', errors='replace') if imp.name else f'ordinal_{imp.ordinal}'
            funcs.append(func_name)

            if func_name in SUSPICIOUS_APIS:
                category, desc = SUSPICIOUS_APIS[func_name]
                flagged[category].append((dll_name, func_name, desc))

        all_imports[dll_name] = funcs

    # Build markdown
    total_funcs = sum(len(v) for v in all_imports.values())
    md = f'## PE Imports & Suspicious APIs — {filename}\n\n'
    md += f'**{len(all_imports)}** DLLs, **{total_funcs}** imported functions'
    if flagged:
        total_flagged = sum(len(v) for v in flagged.values())
        md += f', **{total_flagged}** flagged as suspicious'
    md += '\n\n'

    # Suspicious APIs — single table with category grouping rows
    if flagged:
        md += '---\n\n### Suspicious APIs\n\n'
        md += '| Function | DLL | Description |\n'
        md += '|----------|-----|-------------|\n'
        for category in sorted(flagged.keys()):
            items = sorted(flagged[category])
            md += f'| **{category}** | | |\n'
            for dll, func, desc in items:
                md += f'| `{func}` | {dll} | {desc} |\n'
        md += '\n'
    else:
        md += '---\n\n### Suspicious APIs\n\nNo known suspicious APIs detected.\n\n'

    # Full import table — one row per DLL
    md += '---\n\n### Import Table\n\n'
    md += '| DLL | Count | Key Functions |\n'
    md += '|-----|------:|---------------|\n'
    for dll_name in sorted(all_imports.keys()):
        funcs = all_imports[dll_name]
        preview = ', '.join(funcs[:4])
        if len(funcs) > 4:
            preview += f' … +{len(funcs) - 4} more'
        md += f'| **{dll_name}** | {len(funcs)} | {preview} |\n'

    # Expandable full function lists per DLL
    has_expandable = any(len(v) > 4 for v in all_imports.values())
    if has_expandable:
        md += '\n'
        for dll_name in sorted(all_imports.keys()):
            funcs = all_imports[dll_name]
            if len(funcs) <= 4:
                continue
            func_list = ', '.join(f'`{f}`' for f in funcs)
            md += f'<details><summary><strong>{dll_name}</strong> — all {len(funcs)} imports</summary>\n\n'
            md += f'{func_list}\n\n'
            md += '</details>\n\n'

    pe.close()
    return md


# ---------------------------------------------------------------------------
# PE Exports executor
# ---------------------------------------------------------------------------

def execute_pe_exports(storage, sample, finding):
    """List exported functions."""
    data = _read_sample(storage, sample)
    pe, err = _parse_pe(data)
    if err:
        return f'## PE Exports — {sample.original_filename}\n\n{err}'

    filename = sample.original_filename

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        pe.close()
        return f'## PE Exports — {filename}\n\nNo export table found. This is typical for EXE files.\n'

    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode('utf-8', errors='replace') if exp.name else f'ordinal_{exp.ordinal}'
        exports.append({
            'name': name,
            'ordinal': exp.ordinal,
            'address': exp.address,
        })

    dll_name_raw = getattr(pe.DIRECTORY_ENTRY_EXPORT.struct, 'Name', None)
    dll_name = ''
    if dll_name_raw:
        try:
            dll_name = pe.get_string_at_rva(dll_name_raw).decode('utf-8', errors='replace')
        except Exception:
            pass

    md = f'## PE Exports — {filename}\n\n'
    if dll_name:
        md += f'**DLL Name:** {dll_name}\n\n'
    md += f'Found **{len(exports)}** exported symbol{"s" if len(exports) != 1 else ""}.\n\n'

    if exports:
        md += '| Ordinal | Name | Address |\n'
        md += '|---------|------|---------|\n'
        for exp in exports[:500]:
            md += f'| {exp["ordinal"]} | `{exp["name"]}` | `0x{exp["address"]:08X}` |\n'
        if len(exports) > 500:
            md += f'\n*... and {len(exports) - 500} more exports.*\n'

    pe.close()
    return md


# ---------------------------------------------------------------------------
# Packer Detection executor
# ---------------------------------------------------------------------------

def execute_pe_packer_detection(storage, sample, finding):
    """Check for packing via entropy analysis, known packer section names, and anomalies."""
    data = _read_sample(storage, sample)
    pe, err = _parse_pe(data)
    if err:
        return f'## Packer Detection — {sample.original_filename}\n\n{err}'

    filename = sample.original_filename
    overall_entropy = _entropy(data)
    indicators = []
    detected_packers = set()

    # Check overall entropy
    if overall_entropy > 7.0:
        indicators.append(f'Overall file entropy is **{overall_entropy:.2f}** (> 7.0) — strong packing indicator')
    elif overall_entropy > 6.5:
        indicators.append(f'Overall file entropy is **{overall_entropy:.2f}** (> 6.5) — possible packing')

    # Check section names
    high_entropy_sections = 0
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').replace('\x00', '')
        sect_data = section.get_data()
        ent = _entropy(sect_data)

        if name in KNOWN_PACKER_SECTIONS:
            packer = KNOWN_PACKER_SECTIONS[name]
            detected_packers.add(packer)
            indicators.append(f'Section `{name}` matches known packer: **{packer}**')

        if ent > 7.0 and section.SizeOfRawData > 256:
            high_entropy_sections += 1

    if high_entropy_sections > 0:
        indicators.append(f'{high_entropy_sections} section(s) with entropy > 7.0')

    # Check entry-point byte signatures
    ep_matches = _match_ep_signatures(pe, data)
    for name in sorted(ep_matches):
        detected_packers.add(name)
        indicators.append(f'Entry-point bytes match known packer: **{name}**')

    # Check for small import table (packed binaries often have very few imports)
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        import_count = sum(len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT)
        dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
        if dll_count <= 2 and import_count <= 5:
            indicators.append(f'Very small import table ({dll_count} DLLs, {import_count} functions) — typical of packed binaries')
    else:
        indicators.append('No import table found — binary may be fully packed')

    # Check for overlay (data appended past the last PE section)
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset is not None:
        overlay_size = len(data) - overlay_offset
        if overlay_size > 0:
            pct = overlay_size / len(data) * 100
            indicators.append(
                f'Overlay detected: {overlay_size:,} bytes ({pct:.1f}% of file) '
                f'appended after last PE section — common in packed or bundled executables'
            )
            overlay_data = data[overlay_offset:overlay_offset + min(overlay_size, 4096)]
            overlay_ent = _entropy(overlay_data)
            if overlay_ent > 7.0:
                indicators.append(f'Overlay entropy is **{overlay_ent:.2f}** — likely compressed or encrypted payload')

    # Build report
    md = f'## Packer Detection — {filename}\n\n'
    md += f'**Overall Entropy:** {overall_entropy:.2f} / 8.0\n\n'

    if detected_packers:
        md += f'### Detected Packers\n\n'
        for p in sorted(detected_packers):
            md += f'- **{p}**\n'
        md += '\n'

    if indicators:
        verdict = 'LIKELY PACKED' if (overall_entropy > 7.0 or detected_packers) else 'POSSIBLY PACKED' if overall_entropy > 6.5 else 'INDICATORS PRESENT'
        md += f'### Verdict: {verdict}\n\n'
        md += '### Indicators\n\n'
        for ind in indicators:
            md += f'- {ind}\n'
    else:
        md += '### Verdict: NOT PACKED\n\nNo packing indicators detected.\n'

    # Per-section table — sizes, entropy, permissions, anomaly flags
    md += '\n### Sections\n\n'
    md += '| Section | Virtual Size | Raw Size | Entropy | Permissions | Flags |\n'
    md += '|---------|-------------|----------|---------|-------------|-------|\n'
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').replace('\x00', '')
        vsize = section.Misc_VirtualSize
        rsize = section.SizeOfRawData
        sect_data = section.get_data()
        ent = _entropy(sect_data)

        perms = []
        chars = section.Characteristics
        if chars & 0x20000000:
            perms.append('X')
        if chars & 0x40000000:
            perms.append('R')
        if chars & 0x80000000:
            perms.append('W')
        perm_str = ''.join(perms) or '—'

        flags = []
        if ent > 7.0:
            flags.append('HIGH ENTROPY')
        if 'X' in perms and 'W' in perms:
            flags.append('W+X')
        if vsize > 0 and rsize > 0 and vsize > rsize * 10:
            flags.append('INFLATED')
        flag_str = ', '.join(flags) if flags else '—'

        md += f'| `{name}` | {vsize:,} | {rsize:,} | {ent:.2f} | {perm_str} | {flag_str} |\n'

    pe.close()
    return md


# ---------------------------------------------------------------------------
# PE Resources & Version Info executor
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Compile Time executor
# ---------------------------------------------------------------------------

def execute_compile_time(storage, sample, finding):
    """Extract and analyse the PE compile timestamp for anomalies or timestomping."""
    data = _read_sample(storage, sample)
    pe, err = _parse_pe(data)
    if err:
        return f'## Compile Time — {sample.original_filename}\n\n{err}'

    filename = sample.original_filename
    fh = pe.FILE_HEADER
    timestamp_val = fh.TimeDateStamp
    now = datetime.now(tz=timezone.utc)

    anomalies = []

    # Zero / null timestamp
    if timestamp_val == 0:
        compile_time_str = 'Not set (0x00000000)'
        anomalies.append('Compile timestamp is **zero** — likely stripped or zeroed deliberately')
    else:
        try:
            compile_dt = datetime.fromtimestamp(timestamp_val, tz=timezone.utc)
            compile_time_str = compile_dt.strftime('%Y-%m-%d %H:%M:%S UTC')

            # Future timestamp
            if compile_dt > now:
                anomalies.append(f'Compile time is **in the future** — strong timestomping indicator')

            # Very old (before Windows PE format existed, ~1993)
            if compile_dt.year < 1993:
                anomalies.append(f'Compile time predates the PE format (year {compile_dt.year}) — likely tampered')

            # Epoch-like (1970)
            if compile_dt.year == 1970:
                anomalies.append('Compile time is near Unix epoch (1970) — likely reset or default value')

            # Delphi/Borland epoch (June 19, 1992)
            if compile_dt.year == 1992 and compile_dt.month == 6 and compile_dt.day == 19:
                anomalies.append('Compile time matches Delphi/Borland epoch (1992-06-19) — likely compiled with Delphi or Borland toolchain')

        except (OSError, ValueError, OverflowError):
            compile_time_str = f'Invalid (0x{timestamp_val:08X})'
            anomalies.append('Timestamp value cannot be parsed as a valid date — corrupt or tampered')

    # Check debug directory timestamps for mismatches
    debug_timestamps = []
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            dbg_ts = dbg.struct.TimeDateStamp
            if dbg_ts and dbg_ts != timestamp_val:
                try:
                    dbg_dt = datetime.fromtimestamp(dbg_ts, tz=timezone.utc)
                    debug_timestamps.append(dbg_dt.strftime('%Y-%m-%d %H:%M:%S UTC'))
                except (OSError, ValueError, OverflowError):
                    debug_timestamps.append(f'0x{dbg_ts:08X}')

    if debug_timestamps:
        anomalies.append(
            f'Debug directory timestamp differs from PE header — '
            f'debug: {", ".join(debug_timestamps)}. '
            f'This may indicate timestomping (header was altered but debug info was not)'
        )

    # Build markdown
    md = (
        f'## Compile Time — {filename}\n\n'
        f'| Property | Value |\n'
        f'|----------|-------|\n'
        f'| Raw Value | `0x{timestamp_val:08X}` |\n'
        f'| Compile Time | {compile_time_str} |\n'
    )

    if anomalies:
        md += '\n### Anomalies\n\n'
        for a in anomalies:
            md += f'- {a}\n'
    else:
        md += '\nNo anomalies detected.\n'

    pe.close()
    return md


RESOURCE_TYPE_NAMES = {
    1: 'RT_CURSOR', 2: 'RT_BITMAP', 3: 'RT_ICON', 4: 'RT_MENU',
    5: 'RT_DIALOG', 6: 'RT_STRING', 7: 'RT_FONTDIR', 8: 'RT_FONT',
    9: 'RT_ACCELERATOR', 10: 'RT_RCDATA', 11: 'RT_MESSAGETABLE',
    12: 'RT_GROUP_CURSOR', 14: 'RT_GROUP_ICON', 16: 'RT_VERSION',
    24: 'RT_MANIFEST',
}


def execute_pe_resources(storage, sample, finding):
    """Extract embedded resources, version strings, PDB paths, and manifest info."""
    data = _read_sample(storage, sample)
    pe, err = _parse_pe(data)
    if err:
        return f'## PE Resources — {sample.original_filename}\n\n{err}'

    filename = sample.original_filename
    md = f'## PE Resources & Version Info — {filename}\n\n'

    # Debug / PDB info
    pdb_path = None
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            if hasattr(dbg, 'entry') and hasattr(dbg.entry, 'PdbFileName'):
                raw = dbg.entry.PdbFileName
                pdb_path = raw.decode('utf-8', errors='replace').replace('\x00', '')
                break

    if pdb_path:
        md += f'### Debug Info\n\n'
        md += f'**PDB Path:** `{pdb_path}`\n\n'
        if '\\Users\\' in pdb_path or '/home/' in pdb_path:
            md += '> **Note:** PDB path contains a user directory — may reveal developer identity.\n\n'

    # Version info
    version_info = {}
    if hasattr(pe, 'FileInfo'):
        for fi_list in pe.FileInfo:
            for fi in fi_list:
                if hasattr(fi, 'StringTable'):
                    for st in fi.StringTable:
                        for key, val in st.entries.items():
                            k = key.decode('utf-8', errors='replace')
                            v = val.decode('utf-8', errors='replace')
                            if v.strip():
                                version_info[k] = v

    if version_info:
        md += '### Version Info\n\n'
        md += '| Property | Value |\n'
        md += '|----------|-------|\n'
        for k in sorted(version_info.keys()):
            md += f'| {k} | {version_info[k]} |\n'
        md += '\n'
    else:
        md += '### Version Info\n\nNo version information found.\n\n'

    # Resource directory
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        resource_summary: dict[str, int] = defaultdict(int)
        total_size = 0

        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name = RESOURCE_TYPE_NAMES.get(entry.id, f'TYPE_{entry.id}')
            if entry.name:
                type_name = entry.name.string.decode('utf-8', errors='replace')

            count = 0
            if hasattr(entry, 'directory'):
                for sub in entry.directory.entries:
                    if hasattr(sub, 'directory'):
                        for leaf in sub.directory.entries:
                            count += 1
                            if hasattr(leaf, 'data'):
                                total_size += leaf.data.struct.Size
                    else:
                        count += 1
            resource_summary[type_name] += count

        md += '### Resource Summary\n\n'
        md += '| Type | Count |\n'
        md += '|------|-------|\n'
        for rtype in sorted(resource_summary.keys()):
            md += f'| {rtype} | {resource_summary[rtype]} |\n'
        md += f'\n**Total resource data:** ~{total_size:,} bytes\n\n'

        # Check for embedded PE in resources
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(entry, 'directory'):
                for sub in entry.directory.entries:
                    if hasattr(sub, 'directory'):
                        for leaf in sub.directory.entries:
                            if hasattr(leaf, 'data'):
                                offset = leaf.data.struct.OffsetToData
                                size = leaf.data.struct.Size
                                try:
                                    res_data = pe.get_memory_mapped_image()[offset:offset + min(size, 2)]
                                    if res_data == b'MZ':
                                        type_name = RESOURCE_TYPE_NAMES.get(entry.id, f'TYPE_{entry.id}')
                                        md += f'> **Warning:** Resource `{type_name}` contains an embedded PE executable (MZ header detected).\n\n'
                                except Exception:
                                    pass
    else:
        md += '### Resources\n\nNo resource directory found.\n\n'

    # Manifest (check for UAC elevation requests)
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id == 24:  # RT_MANIFEST
                try:
                    for sub in entry.directory.entries:
                        for leaf in sub.directory.entries:
                            offset = leaf.data.struct.OffsetToData
                            size = leaf.data.struct.Size
                            manifest_data = pe.get_memory_mapped_image()[offset:offset + size]
                            manifest_text = manifest_data.decode('utf-8', errors='replace')
                            if 'requireAdministrator' in manifest_text:
                                md += '> **Warning:** Manifest requests **administrator** elevation (UAC).\n\n'
                            elif 'highestAvailable' in manifest_text:
                                md += '> **Note:** Manifest requests **highestAvailable** elevation.\n\n'
                except Exception:
                    pass

    pe.close()
    return md
