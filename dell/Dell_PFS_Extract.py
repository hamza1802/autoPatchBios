#! /usr/bin/python
"""
Dell PFS (Platform Firmware Storage) Extractor
Extracts UEFI firmware volumes and modules from Dell BIOS update packages.
Supports raw .hdr/.bin PFS files and .exe packages with embedded PFS payload.
"""

from argparse import RawTextHelpFormatter
import argparse
import binascii
import os
import struct
import zlib
import uuid

VERSION = '0.1'

# Magic signatures
PFS_HEAD_MAGIC = b'PFS.HDR.'
PFS_FOOT_MAGIC = b'PFS.FTR.'
ZLIB_MAGIC     = b'\x78\x9C'
LZMA_MAGIC     = b'\xFD7zXZ'

# PFS Header layout (40 bytes):
#   8s  magic
#   I   unknown (usually 1)
#   I   version (1 or 2)
#   16s guid
#   I   body_size
#   I   unknown
PFS_HDR_FMT = '<8sII16sII'
PFS_HDR_LEN = struct.calcsize(PFS_HDR_FMT)  # 40

# PFS Footer layout (16 bytes):
#   8s  magic
#   I   crc32
#   I   total_size (header + body + footer)
PFS_FOOT_FMT = '<8sII'
PFS_FOOT_LEN = struct.calcsize(PFS_FOOT_FMT)  # 16

# PFS Entry Header layout (40 bytes):
#   16s guid
#   I   version_info
#   I   type
#   I   data_size
#   I   data_sig_size
#   I   meta_size
#   I   meta_sig_size
PFS_ENTRY_FMT = '<16sIIIIII'
PFS_ENTRY_HDR_LEN = struct.calcsize(PFS_ENTRY_FMT)  # 40

# Entry type labels
ENTRY_TYPE = {
    0x00: 'BIOS',
    0x01: 'Delta',
    0x02: 'Compressed',
    0x04: 'Model',
    0x07: 'SpiState',
    0x10: 'Manifest',
}

parser = argparse.ArgumentParser(
    prog='Dell_PFS_Extract',
    description='Extract UEFI firmware from Dell PFS BIOS update packages.\n'
                'Supports raw .hdr/.bin PFS files and .exe packages with embedded PFS.',
    formatter_class=RawTextHelpFormatter
)
parser.add_argument('source', metavar='FILE', help='Dell BIOS update file (.hdr, .bin, or .exe)')
parser.add_argument('-o', '--output', metavar='DIR', default=None,
                    help='output directory (default: <source>_extracted/)')
parser.add_argument('--no-nested', action='store_true',
                    help='do not recurse into nested PFS containers')
parser.add_argument('--version', action='store_true', help='show version and exit')

args = parser.parse_args()


def fmt_guid(raw_bytes):
    h = binascii.hexlify(raw_bytes).decode()
    return str(uuid.UUID(
        '{' +
        h[6:8] + h[4:6] + h[2:4] + h[0:2] + '-' +
        h[10:12] + h[8:10] + '-' +
        h[14:16] + h[12:14] + '-' +
        h[16:20] + '-' +
        h[20:32] +
        '}'
    )).upper()


def safe_mkdir(path):
    os.makedirs(path, exist_ok=True)


def decompress_zlib(data):
    try:
        return zlib.decompress(data)
    except zlib.error:
        # Try stripping a potential 2-byte header offset
        for offset in range(0, min(16, len(data))):
            try:
                return zlib.decompress(data[offset:])
            except zlib.error:
                continue
    return None


def find_pfs_offset(data):
    """Locate PFS.HDR. magic within a blob (handles .exe wrappers)."""
    offset = data.find(PFS_HEAD_MAGIC)
    return offset


def parse_pfs_header(data, offset):
    if len(data) < offset + PFS_HDR_LEN:
        return None
    magic, unk, version, guid_raw, body_size, unk2 = struct.unpack_from(PFS_HDR_FMT, data, offset)
    if magic != PFS_HEAD_MAGIC:
        return None
    return {
        'offset': offset,
        'version': version,
        'guid': fmt_guid(guid_raw),
        'body_size': body_size,
        'body_offset': offset + PFS_HDR_LEN,
    }


def parse_pfs_footer(data, offset):
    if len(data) < offset + PFS_FOOT_LEN:
        return None
    magic, crc, total_size = struct.unpack_from(PFS_FOOT_FMT, data, offset)
    if magic != PFS_FOOT_MAGIC:
        return None
    return {'crc': crc, 'total_size': total_size}


def parse_entries(data, body_offset, body_size):
    entries = []
    pos = body_offset
    end = body_offset + body_size
    index = 0

    while pos + PFS_ENTRY_HDR_LEN <= end:
        guid_raw, ver_info, etype, data_size, data_sig_size, meta_size, meta_sig_size = \
            struct.unpack_from(PFS_ENTRY_FMT, data, pos)

        hdr_end = pos + PFS_ENTRY_HDR_LEN
        payload_end = hdr_end + data_size + data_sig_size + meta_size + meta_sig_size

        if payload_end > end + PFS_FOOT_LEN:
            # Misaligned — likely hit padding or footer
            break

        entry_data     = data[hdr_end : hdr_end + data_size]
        entry_data_sig = data[hdr_end + data_size : hdr_end + data_size + data_sig_size]
        entry_meta     = data[hdr_end + data_size + data_sig_size :
                               hdr_end + data_size + data_sig_size + meta_size]

        entries.append({
            'index': index,
            'guid': fmt_guid(guid_raw),
            'type': ENTRY_TYPE.get(etype, 'Type_{:02X}'.format(etype)),
            'type_id': etype,
            'data': entry_data,
            'data_sig': entry_data_sig,
            'meta': entry_meta,
        })

        pos = hdr_end + data_size + data_sig_size + meta_size + meta_sig_size
        index += 1

    return entries


def extract_pfs(data, out_dir, depth=0, label='PFS'):
    indent = '  ' * depth

    pfs_offset = find_pfs_offset(data)
    if pfs_offset < 0:
        print(indent + '[!] No PFS.HDR. magic found in data.')
        return False

    if pfs_offset > 0:
        print(indent + '[i] PFS payload found at offset 0x{:X} (skipped {:d} wrapper bytes)'.format(
            pfs_offset, pfs_offset))

    hdr = parse_pfs_header(data, pfs_offset)
    if not hdr:
        print(indent + '[!] Failed to parse PFS header.')
        return False

    print(indent + '[+] {} v{} | GUID {} | body {:,} bytes'.format(
        label, hdr['version'], hdr['guid'], hdr['body_size']))

    entries = parse_entries(data, hdr['body_offset'], hdr['body_size'])

    if not entries:
        print(indent + '[!] No entries parsed.')
        return False

    print(indent + '    {} entr{} found.'.format(len(entries), 'y' if len(entries) == 1 else 'ies'))

    safe_mkdir(out_dir)

    for e in entries:
        tag = '[{:02d}] {} ({})'.format(e['index'], e['type'], e['guid'])
        print(indent + '  ' + tag)

        payload = e['data']

        # Attempt zlib decompression if data starts with zlib magic or entry type says compressed
        if payload[:2] == ZLIB_MAGIC or e['type_id'] == 0x02:
            decompressed = decompress_zlib(payload)
            if decompressed:
                print(indent + '      Decompressed: {:,} -> {:,} bytes'.format(
                    len(payload), len(decompressed)))
                payload = decompressed

        fname_base = '{:02d}_{}_{}' .format(e['index'], e['type'], e['guid'])
        out_path   = os.path.join(out_dir, fname_base + '.bin')
        with open(out_path, 'wb') as f:
            f.write(payload)
        print(indent + '      Saved -> {}'.format(os.path.basename(out_path)))

        if e['meta']:
            meta_path = os.path.join(out_dir, fname_base + '.meta')
            with open(meta_path, 'wb') as f:
                f.write(e['meta'])

        # Recurse into nested PFS containers
        if not args.no_nested and PFS_HEAD_MAGIC in payload:
            nested_dir = os.path.join(out_dir, fname_base + '_nested')
            print(indent + '      -> Nested PFS detected, recursing...')
            extract_pfs(payload, nested_dir, depth + 1, label='Nested-PFS[{:02d}]'.format(e['index']))

    # Verify footer CRC
    foot_offset = hdr['body_offset'] + hdr['body_size']
    footer = parse_pfs_footer(data, foot_offset)
    if footer:
        body_bytes = data[pfs_offset : foot_offset]
        computed = zlib.crc32(body_bytes) & 0xFFFFFFFF
        status = 'OK' if computed == footer['crc'] else 'MISMATCH (got {:08X}, expected {:08X})'.format(
            computed, footer['crc'])
        print(indent + '    Footer CRC: ' + status)

    return True


def main():
    if args.version:
        print('\nDell PFS Extractor v' + VERSION)
        return

    source = args.source
    if not os.path.exists(source):
        print('File not found: ' + source)
        return

    with open(source, 'rb') as f:
        data = f.read()

    out_dir = args.output
    if not out_dir:
        base = os.path.splitext(source)[0]
        out_dir = base + '_extracted'

    print('\nDell PFS Extractor v{}'.format(VERSION))
    print('Source : {}'.format(source))
    print('Output : {}'.format(out_dir))
    print('')

    ok = extract_pfs(data, out_dir)

    if ok:
        print('\nExtraction complete.')
        print('Output folder: ' + out_dir)
        print('\nNext step: open extracted .bin files in UEFITool to identify')
        print('DXE modules and copy relevant .ffs files into dell/patch/DXE/')
    else:
        print('\nExtraction failed.')


main()
