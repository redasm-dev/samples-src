#!/usr/bin/env python3

"""
Builds a minimal, hand-crafted PE32 (x86) test DLL
with this export table (no compiler involved):

ORDINAL  NAME                 RVA        KIND
100      NormalExport         0x1000     code (in .text)
101      ForwardedByName      0x20a4     forwarder string "FWDTGT.dll.TargetByName"
102                           0x1008     ordinal-nly, code (in .text)
103      ForwardedByOrdinal   0x20bc     forwarder string "FWDTGT.dll.#42"
104      AnotherNormalExport  0x1010     code (in .text)

Export ordinal base is deliberately non-zero (100) since real-world DLLs
almost never start at 1, and a loader that hardcodes ordinal_base=1 is a
classic, easy-to-miss bug.
"""
import struct

PAGE = 0x1000
FILE_ALIGN = 0x200
IMAGE_BASE = 0x10000000


def align(v, a):
    return (v + a - 1) & ~(a - 1)


class Section:
    def __init__(self, name, data, rva, characteristics):
        self.name = name
        self.data = data
        self.rva = rva
        self.vsize = len(data)
        self.raw_size = align(len(data), FILE_ALIGN)
        self.characteristics = characteristics
        self.raw_offset = None  # filled in later

# ---------------------------------------------------------------------------
# Export table construction
# ---------------------------------------------------------------------------


DLL_NAME = b"testfwd.dll\x00"
ORDINAL_BASE = 100

# (export_name_or_None, kind, payload)
#   kind == "code"      -> payload = offset into text_code entrypoints (0..3)
#   kind == "forward"   -> payload = forwarder string (bytes, NUL-terminated)
#   kind == "ordinal_only_code" -> payload = offset into text entrypoints,
#                                   exported by ordinal only (no name)
EXPORTS = [
    ("NormalExport", "code", 0),
    ("ForwardedByName", "forward", b"FWDTGT.dll.TargetByName\x00"),
    (None, "ordinal_only_code", 1),          # ordinal-only, real code
    ("ForwardedByOrdinal", "forward", b"FWDTGT.dll.#42\x00"),
    ("AnotherNormalExport", "code", 2),
]


def build_pe():
    text_code = bytes([0x55, 0x8B, 0xEC, 0x33, 0xC0, 0x5D, 0xC3, 0x90]) * 8
    text = Section(".text", text_code, rva=PAGE, characteristics=0x60000020)

    text_entry_stride = 8  # bytes between synthetic "entry points" we hand out

    cursor = align(PAGE + len(text.data), PAGE)
    edata_rva = cursor

    # --- Lay out the export directory's sub-structures ---
    # We need, in order (order among these is not RVA-significant, but the
    # IMAGE_EXPORT_DIRECTORY fields must point at wherever we put them):
    #   IMAGE_EXPORT_DIRECTORY header           (40 bytes)
    #   AddressOfFunctions  : u32[NumOfFunctions]
    #   AddressOfNames      : u32[NumOfNames]      (sorted by string, ascending)
    #   AddressOfNameOrdinals: u16[NumOfNames]
    #   DLL name string
    #   per-export name strings
    #   forwarder strings
    #
    # NumOfFunctions counts ALL exports (named + ordinal-only).
    # NumOfNames counts only the named ones.

    named = [e for e in EXPORTS if e[0] is not None]
    num_functions = len(EXPORTS)
    num_names = len(named)

    header_size = 40
    func_table_off = header_size
    func_table_size = 4 * num_functions

    names_table_off = func_table_off + func_table_size
    names_table_size = 4 * num_names

    ord_table_off = names_table_off + names_table_size
    ord_table_size = 2 * num_names

    strings_off = ord_table_off + ord_table_size

    # Build the string blob: DLL name first, then export names (sorted!),
    # then forwarder strings. AddressOfNames must be lexicographically sorted
    # by name since the loader binary-searches it -- this is a critical
    # invariant real-world tooling (and IDA) both rely on.
    blob = bytearray()
    blob += DLL_NAME
    dll_name_rva = edata_rva + strings_off + 0

    name_rvas = {}  # export_name -> rva
    for name, kind, payload in EXPORTS:
        if name is None:
            continue
        off = len(blob)
        blob += name.encode("ascii") + b"\x00"
        name_rvas[name] = edata_rva + strings_off + off

    forwarder_rvas = {}  # index in EXPORTS -> rva of forwarder string
    for i, (name, kind, payload) in enumerate(EXPORTS):
        if kind == "forward":
            off = len(blob)
            blob += payload
            forwarder_rvas[i] = edata_rva + strings_off + off

    strings_size = len(blob)
    total_edata_size = strings_off + strings_size

    # AddressOfFunctions: one slot per export, in ordinal order
    # (index 0 == ordinal ORDINAL_BASE).
    func_rvas = []
    for name, kind, payload in EXPORTS:
        if kind == "code" or kind == "ordinal_only_code":
            func_rvas.append(text.rva + payload * text_entry_stride)
        elif kind == "forward":
            idx = EXPORTS.index((name, kind, payload))
            func_rvas.append(forwarder_rvas[idx])
        else:
            raise ValueError(kind)

    # AddressOfNames + AddressOfNameOrdinals, sorted by name ascending.
    sorted_named = sorted(named, key=lambda e: e[0])
    names_rvas_sorted = [name_rvas[n] for (n, k, p) in sorted_named]
    name_ordinal_indices = [EXPORTS.index(e) for e in sorted_named]  # 0-based index into func table

    # --- Pack the actual bytes ---
    edata = bytearray(total_edata_size)

    # IMAGE_EXPORT_DIRECTORY
    def pack_export_dir():
        return struct.pack(
            "<IIHHIIIIIII",
            0,                      # Characteristics
            0,                      # TimeDateStamp
            0, 0,                   # MajorVersion, MinorVersion
            dll_name_rva,           # Name
            ORDINAL_BASE,           # Base
            num_functions,          # NumberOfFunctions
            num_names,              # NumberOfNames
            edata_rva + func_table_off,   # AddressOfFunctions
            edata_rva + names_table_off,  # AddressOfNames
            edata_rva + ord_table_off,    # AddressOfNameOrdinals
        )

    hdr = pack_export_dir()
    assert len(hdr) == header_size, len(hdr)
    edata[0:header_size] = hdr

    off = func_table_off
    for rva in func_rvas:
        struct.pack_into("<I", edata, off, rva)
        off += 4

    off = names_table_off
    for rva in names_rvas_sorted:
        struct.pack_into("<I", edata, off, rva)
        off += 4

    off = ord_table_off
    for idx in name_ordinal_indices:
        struct.pack_into("<H", edata, off, idx)
        off += 2

    edata[strings_off:strings_off + strings_size] = blob

    edata_section = Section(".edata", bytes(edata), edata_rva,
                            characteristics=0x40000040)  # INITIALIZED_DATA|READ

    # --- Lay out file offsets / headers ---
    sections = [text, edata_section]

    num_sections = len(sections)
    dos_header_size = 0x40
    pe_sig_size = 4
    file_header_size = 20
    opt_header_size = 224  # PE32 optional header w/ 16 data directories
    section_header_size = 40

    headers_total = (dos_header_size + pe_sig_size + file_header_size +
                     opt_header_size + section_header_size * num_sections)
    size_of_headers = align(headers_total, FILE_ALIGN)

    raw_cursor = size_of_headers
    for s in sections:
        s.raw_offset = raw_cursor
        raw_cursor += s.raw_size

    # SizeOfImage = headers (rounded to PAGE) + each section's virtual size rounded to PAGE
    size_of_image = align(size_of_headers, PAGE)
    for s in sections:
        size_of_image += align(s.vsize, PAGE)

    entry_rva = text.rva  # DllMain-ish stub at very start of .text

    # ---- DOS header + stub ----
    dos = bytearray(dos_header_size)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, dos_header_size + pe_sig_size)  # e_lfanew -> right after stub (no real stub code)
    # NOTE: e_lfanew points exactly at PE sig location below.

    pe_offset = dos_header_size  # since we put PE sig immediately after the 0x40-byte dos header
    struct.pack_into("<I", dos, 0x3C, pe_offset)

    # ---- COFF file header ----
    machine = 0x014C  # IMAGE_FILE_MACHINE_I386
    characteristics = 0x2102  # EXECUTABLE_IMAGE | 32BIT_MACHINE | DLL
    coff = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        0,              # TimeDateStamp
        0,              # PointerToSymbolTable
        0,              # NumberOfSymbols
        opt_header_size,
        characteristics,
    )

    # ---- Optional header (PE32) ----
    image_base = IMAGE_BASE
    section_alignment = PAGE
    file_alignment = FILE_ALIGN

    size_of_code = text.raw_size
    size_of_init_data = edata_section.raw_size
    size_of_uninit_data = 0

    base_of_code = text.rva
    base_of_data = edata_section.rva

    opt = bytearray(opt_header_size)
    struct.pack_into("<H", opt, 0, 0x10B)         # Magic = PE32
    struct.pack_into("<B", opt, 2, 1)             # MajorLinkerVersion
    struct.pack_into("<B", opt, 3, 0)             # MinorLinkerVersion
    struct.pack_into("<I", opt, 4, size_of_code)
    struct.pack_into("<I", opt, 8, size_of_init_data)
    struct.pack_into("<I", opt, 12, size_of_uninit_data)
    struct.pack_into("<I", opt, 16, entry_rva)    # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, base_of_code)
    struct.pack_into("<I", opt, 24, base_of_data)
    struct.pack_into("<I", opt, 28, image_base)
    struct.pack_into("<I", opt, 32, section_alignment)
    struct.pack_into("<I", opt, 36, file_alignment)
    struct.pack_into("<H", opt, 40, 6)            # MajorOSVersion
    struct.pack_into("<H", opt, 42, 0)
    struct.pack_into("<H", opt, 44, 0)            # MajorImageVersion
    struct.pack_into("<H", opt, 46, 0)
    struct.pack_into("<H", opt, 48, 6)            # MajorSubsystemVersion
    struct.pack_into("<H", opt, 50, 0)
    struct.pack_into("<I", opt, 52, 0)            # Win32VersionValue
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, size_of_headers)
    struct.pack_into("<I", opt, 64, 0)            # CheckSum
    struct.pack_into("<H", opt, 68, 2)            # Subsystem = WINDOWS_GUI
    struct.pack_into("<H", opt, 70, 0x0160)       # DllCharacteristics (NX+terminate-on-violation-ish, harmless flags)
    struct.pack_into("<I", opt, 72, 0x100000)     # SizeOfStackReserve
    struct.pack_into("<I", opt, 76, 0x1000)       # SizeOfStackCommit
    struct.pack_into("<I", opt, 80, 0x100000)     # SizeOfHeapReserve
    struct.pack_into("<I", opt, 84, 0x1000)       # SizeOfHeapCommit
    struct.pack_into("<I", opt, 88, 0)            # LoaderFlags
    struct.pack_into("<I", opt, 92, 16)           # NumberOfRvaAndSizes

    # Data directories start at offset 96, 8 bytes each, 16 entries.
    dd_off = 96
    # Directory 0 = Export Table
    struct.pack_into("<II", opt, dd_off + 0 * 8, edata_rva, total_edata_size)
    # all others zero (already zero-initialized)

    # ---- Section headers ----
    sect_headers = bytearray()
    for s in sections:
        name_field = s.name.encode("ascii")[:8]
        name_field = name_field + b"\x00" * (8 - len(name_field))
        sh = struct.pack(
            "<8sIIIIIIHHI",
            name_field,
            s.vsize,            # VirtualSize
            s.rva,              # VirtualAddress
            s.raw_size,         # SizeOfRawData
            s.raw_offset,       # PointerToRawData
            0, 0,               # PointerToRelocations, PointerToLinenumbers
            0, 0,               # NumberOfRelocations, NumberOfLinenumbers
            s.characteristics,
        )
        sect_headers += sh

    # ---- Assemble file ----
    out = bytearray()
    out += dos
    # pad dos stub to pe_offset already exact size match since dos_header_size==pe_offset
    out += b"PE\x00\x00"
    out += coff
    out += opt
    out += sect_headers
    out += b"\x00" * (size_of_headers - len(out))

    for s in sections:
        assert s.raw_offset == len(out), (s.name, s.raw_offset, len(out))
        out += s.data
        out += b"\x00" * (s.raw_size - len(s.data))

    return bytes(out)


if __name__ == "__main__":
    data = build_pe()
    with open("testfwd.dll", "wb") as f:
        f.write(data)
    print(f"wrote testfwd.dll, {len(data)} bytes")
