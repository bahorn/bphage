"""
Better trickz
"""
import struct


def read_qword(f, offset):
    return struct.unpack('<Q', f[offset:offset + 8])[0]


def read_dword(f, offset):
    return struct.unpack('<I', f[offset:offset + 4])[0]


def read_signed_dword(f, offset):
    return struct.unpack('<i', f[offset:offset + 4])[0]


def read_word(f, offset):
    return struct.unpack('<H', f[offset:offset + 2])[0]


def write_bytes(f, offset, data):
    f[offset:offset + len(data)] = data


def find_main(f):
    """
    At offset 27 of _start there is a offset to main()
    """
    e_entry_offset = 16 + 2 + 2 + 4
    e_entry = read_qword(f, e_entry_offset)

    main_offset = read_signed_dword(f, e_entry + 27)

    # 31 is the RIP offset used from e_entry
    return e_entry + main_offset + 31


def main():
    f = bytearray(open('/bin/bash', 'rb').read())
    print(hex(find_main(f)))


if __name__ == "__main__":
    main()
