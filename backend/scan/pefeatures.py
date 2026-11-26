"""Static features of a Windows program (PE file): 99 numbers, no code is ever run.

The same function is used for training and for scanning, so the two can never drift apart.
Deliberately NOT used: build time, linker version, ASLR/DEP flags, names of imported DLLs. They only tell "old or new compiler",
which would make a model look clever on a dataset whose malware is older than its clean files.
"""
from __future__ import annotations  # type hints may refer to names defined later

import math  # log
import re  # finds IP addresses in text
from typing import Optional  # "a value or None"

import numpy as np  # the feature vector is a numpy array

try:
    import pefile  # reads the structure of a Windows program
except ImportError:  # the scan service still works without it, the model just stays off
    pefile = None

MAX_READ = 16 * 1024 * 1024  # a file is read at most this far for strings and histograms
# section names that normal compilers produce
STANDARD_SECTIONS = {".text", ".data", ".rdata", ".idata", ".edata", ".pdata", ".rsrc", ".reloc", ".bss", ".tls", ".crt", ".didat", ".gfids", "code", "data", "bss", ".xdata", ".00cfg", ".retplne", "_rdata"}
# section names that packers produce
PACKER_SECTIONS = ("upx", ".aspack", ".adata", "themida", ".vmp", ".petite", ".mpress", ".nsp", ".enigma", ".pec", ".packed", ".yp", "fsg", ".rlpack", ".boom")

# Windows functions grouped by what they let a program do
API_GROUPS = {
    "inject": ("virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection", "setthreadcontext", "queueuserapc", "readprocessmemory", "ntwritevirtualmemory", "rtlcreateuserthread"),  # code injection
    "memory": ("virtualalloc", "virtualprotect", "virtualprotectex", "heapcreate"),  # memory tricks
    "dynload": ("loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "getprocaddress", "ldrloaddll"),  # loads other functions at run time
    "network": ("internetopena", "internetopenw", "internetopenurla", "internetreadfile", "urldownloadtofilea", "urldownloadtofilew", "httpsendrequesta", "winhttpopen", "winhttpsendrequest", "wsastartup", "socket", "connect", "send", "recv", "gethostbyname", "getaddrinfo", "internetconnecta"),  # network access
    "persist": ("regsetvaluea", "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw", "createservicea", "createservicew", "startservicea", "openscmanagera", "openscmanagerw"),  # starts with Windows
    "crypto": ("cryptencrypt", "cryptdecrypt", "cryptacquirecontexta", "cryptacquirecontextw", "cryptgenkey", "cryptderivekey", "bcryptencrypt", "cryptcreatehash", "cryptimportkey"),  # encryption
    "antidebug": ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa", "gettickcount", "queryperformancecounter", "ntsetinformationthread"),  # hides from analysts
    "process": ("createprocessa", "createprocessw", "shellexecutea", "shellexecutew", "shellexecuteexa", "winexec", "createprocessasusera", "createtoolhelp32snapshot", "process32first", "process32next", "openprocess", "terminateprocess"),  # starts or stops programs
    "files": ("deletefilea", "deletefilew", "movefileexa", "findfirstfilea", "findfirstfilew", "findnextfilea", "copyfilea", "setfileattributesa", "getlogicaldrives", "getdrivetypea"),  # walks and changes files
    "spy": ("setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeyboardstate", "getforegroundwindow", "getwindowtexta", "bitblt", "getclipboarddata", "capcreatecapturewindowa"),  # keylogging and screenshots
    "privilege": ("adjusttokenprivileges", "openprocesstoken", "lookupprivilegevaluea", "lookupprivilegevaluew", "impersonateloggedonuser"),  # raises its rights
}


def _base(name: str) -> str:
    """ANSI / wide twins of one Windows function are the same API (CreateProcessA == CreateProcessW)."""
    return name[:-1] if len(name) > 4 and name[-1] in "aw" else name  # drop the trailing A or W


API_BASES = {g: {_base(a) for a in apis} for g, apis in API_GROUPS.items()}  # the same groups without the A / W twins
# text pieces that malware often contains
STRING_PATTERNS = [b"http://", b"https://", b".exe", b".dll", b"cmd.exe", b"powershell", b"currentversion\\run", b".onion", b"bitcoin", b"wallet", b"decrypt", b"your files", b"ransom", b"password", b"keylog", b"botnet", b"\\\\.\\pipe", b"temp%", b"appdata", b"schtasks", b"net user", b"vssadmin", b"/c ", b"user-agent"]
IP_RE = re.compile(rb"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")  # an IPv4 address inside the file

# the name of every number, in the order extract() produces them
NAMES = (
    ["size_log", "entropy_all", "zero_share", "printable_share"] + [f"hist_{i}" for i in range(16)]  # whole-file statistics
    + ["is_x64", "is_dll", "subsystem_gui", "subsystem_console", "size_code_log", "size_idata_log", "size_udata_log", "size_image_log", "size_headers_log",
       "entry_in_first_section", "entry_outside_sections", "entry_in_nonexec", "checksum_zero", "n_sections", "has_debug", "has_tls", "has_relocs", "has_signature",
       "n_exports_log", "n_import_dlls", "n_import_funcs_log", "funcs_per_dll", "has_delay_imports", "has_resources", "n_resources_log", "max_resource_entropy", "resource_share"]  # header facts
    + ["sec_entropy_mean", "sec_entropy_max", "sec_entropy_min", "sec_exec", "sec_write_exec", "sec_high_entropy", "sec_zero_raw", "sec_vr_max", "sec_vr_mean",
       "sec_nonstandard", "sec_packer_name", "overlay_share", "overlay_entropy", "code_share"]  # section facts
    + [f"api_{g}" for g in API_GROUPS] + ["api_total_log", "api_dynload_only"]  # what the imported functions allow
    + [f"str_{p.decode(errors='ignore').strip()[:12]}" for p in STRING_PATTERNS] + ["str_ip_count"]  # text pieces
)
N_FEATURES = len(NAMES)  # how many numbers one program gives


def entropy(b: bytes) -> float:
    """Shannon entropy in bits per byte (0 = all the same, 8 = random or packed)."""
    if not b:  # nothing to measure
        return 0.0
    c = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256).astype(np.float64)  # how often every byte value occurs
    p = c[c > 0] / len(b)  # their shares
    return float(-(p * np.log2(p)).sum())  # the entropy formula


def _l(x) -> float:
    """log(1 + x) for counts and sizes, so huge values do not dominate."""
    return math.log1p(max(float(x), 0.0))


def extract(data: bytes) -> Optional[np.ndarray]:
    """Return the feature vector, or None when this is not a readable PE file."""
    if pefile is None or len(data) < 0x200 or data[:2] != b"MZ":  # no library, too small, or no 'MZ' header
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)  # parse the headers only
        pe.parse_data_directories(directories=[  # then the tables we need
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"], pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"], pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
    except Exception:  # a damaged or fake PE
        return None
    try:
        return _vector(pe, data)  # the numbers
    except Exception:  # anything odd inside the file
        return None
    finally:
        pe.close()  # always release the parser


def _vector(pe, data: bytes) -> np.ndarray:
    """Builds the feature vector of one parsed program."""
    head = data[:MAX_READ]  # the part of the file we read
    arr = np.frombuffer(head, dtype=np.uint8)  # as numbers
    hist = np.bincount(arr >> 4, minlength=16).astype(np.float64) / max(len(arr), 1)  # 16-bucket histogram of byte values
    printable = float(((arr >= 32) & (arr < 127)).mean())  # share of readable characters
    f: list[float] = [_l(len(data)), entropy(head[:1 << 20]), float((arr == 0).mean()), printable, *hist.tolist()]  # whole-file statistics

    oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER  # the two main headers
    sub = getattr(oh, "Subsystem", 0)  # window program (2) or console program (3)
    secs = list(pe.sections)  # the sections
    ep = oh.AddressOfEntryPoint  # where the program starts
    ep_sec = next((i for i, s in enumerate(secs) if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)), -1)  # the section that holds the entry point
    dd = oh.DATA_DIRECTORY  # table of tables

    def has(i):
        """1.0 when data directory number i exists."""
        return float(len(dd) > i and dd[i].VirtualAddress != 0)

    exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0  # exported functions
    imports = [(e.dll, [i.name.decode("latin-1").lower() if i.name else f"ord{i.ordinal}" for i in e.imports]) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]  # (dll, functions)
    n_funcs = sum(len(fs) for _, fs in imports)  # imported functions in all
    res_sizes, res_ent = [], 0.0  # resource sizes and the highest resource entropy
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):  # walk the resource tree
        for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:  # types
            for n in getattr(t, "directory", None).entries if hasattr(t, "directory") else []:  # names
                for l in getattr(n, "directory", None).entries if hasattr(n, "directory") else []:  # languages
                    d = l.data.struct  # the resource itself
                    res_sizes.append(d.Size)  # its size
                    if d.Size and len(res_sizes) <= 40:  # measure the first 40 only
                        try:
                            res_ent = max(res_ent, entropy(pe.get_data(d.OffsetToData, min(d.Size, 1 << 18))))  # packed data hides in resources
                        except Exception:  # unreadable resource
                            pass
    f += [  # header facts
        float(fh.Machine == 0x8664), float(bool(fh.Characteristics & 0x2000)), float(sub == 2), float(sub == 3),  # 64-bit, dll, window, console
        _l(oh.SizeOfCode), _l(oh.SizeOfInitializedData), _l(oh.SizeOfUninitializedData), _l(oh.SizeOfImage), _l(oh.SizeOfHeaders),  # sizes
        float(ep_sec == 0), float(ep_sec == -1), float(ep_sec >= 0 and not secs[ep_sec].Characteristics & 0x20000000),  # entry point oddities
        float(oh.CheckSum == 0), float(len(secs)), has(6), has(9), has(5), has(4),  # checksum, sections, debug, tls, relocations, signature
        _l(exports), float(len(imports)), _l(n_funcs), n_funcs / max(len(imports), 1), has(13), has(2), _l(len(res_sizes)), res_ent, sum(res_sizes) / max(len(data), 1),  # exports, imports, resources
    ]

    ents, wx, hi, zr, vr, nonstd, packer, execs = [], 0, 0, 0, [], 0, 0, 0  # section statistics
    last_end = 0  # where the last section ends in the file
    for s in secs:  # every section
        raw = s.get_data()[:1 << 20]  # its bytes (first megabyte)
        e = entropy(raw)  # how random they are
        ents.append(e)
        ch = s.Characteristics  # its flags
        execs += bool(ch & 0x20000000)  # executable
        wx += bool(ch & 0x20000000 and ch & 0x80000000)  # writable AND executable (self-modifying code)
        hi += e > 7.0  # very high entropy: packed or encrypted
        zr += s.SizeOfRawData == 0  # empty on disk (filled at run time)
        vr.append(s.Misc_VirtualSize / max(s.SizeOfRawData, 1) if s.SizeOfRawData else 0.0)  # grows a lot in memory
        nm = s.Name.rstrip(b"\x00").decode("latin-1").lower()  # section name
        nonstd += nm not in STANDARD_SECTIONS  # unusual name
        packer += nm.startswith(PACKER_SECTIONS)  # a packer's name
        last_end = max(last_end, s.PointerToRawData + s.SizeOfRawData)  # end of the last section
    overlay = data[last_end:] if 0 < last_end < len(data) else b""  # extra bytes after the last section
    code = sum(s.SizeOfRawData for s in secs if s.Characteristics & 0x20000000)  # bytes of code
    f += [  # section facts
        float(np.mean(ents)) if ents else 0.0, max(ents, default=0.0), min(ents, default=0.0), float(execs), float(wx), float(hi), float(zr),  # entropy and flags
        min(max(vr, default=0.0), 50.0), min(float(np.mean(vr)) if vr else 0.0, 50.0), float(nonstd), float(packer),  # growth, odd names, packer names
        len(overlay) / max(len(data), 1), entropy(overlay[:1 << 20]), code / max(len(data), 1),  # overlay and code share
    ]

    names = [n for _, fs in imports for n in fs]  # every imported function name
    stripped = [_base(n) for n in names]  # without A / W
    counts = [sum(1 for n in stripped if n in bases) for bases in API_BASES.values()]  # how many functions per group
    f += [_l(c) for c in counts] + [_l(sum(counts)), float(n_funcs > 0 and counts[2] >= n_funcs * 0.5)]  # per group, total, and "mostly run-time loading" (a packed stub)

    low = head.lower()  # lower case for text matching
    f += [_l(low.count(p)) for p in STRING_PATTERNS] + [_l(len(IP_RE.findall(head[:4 << 20])))]  # text pieces and IP addresses
    v = np.asarray(f, dtype=np.float32)  # the vector
    assert v.shape[0] == N_FEATURES, (v.shape, N_FEATURES)  # names and numbers must stay in step
    return np.nan_to_num(v, nan=0.0, posinf=0.0, neginf=0.0)  # no NaN or infinity ever reaches the model
