"""
Better trickz

## Finding main

in _start, there is a `lea` that loads a relative offset to main, passed as an
argument to __libc_start_main.

## Finding the symbolz

.dynamic is a section that has a list of tags that describe where to find:
* .dynsym
* .dynstr
* the JMPREL we care about.

so find those, then process jmprel checking each symbol against those.

we can ignore sizes as we assume everything will be found!

"""
import os
import struct
from enum import Enum

SHT_STRTAB = 0x03
SHT_DYNAMIC = 0x06


class Dynamic(Enum):
    DT_NULL = 0
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_JMPREL = 23


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


def to_nullbyte(f, offset):
    res = bytearray()
    for i in f[offset:]:
        if i == 0:
            return res
        res.append(i)


def create_setup(start_offset, dlopen_offset, dlsym_offset):
    new_dlopen_offset = dlopen_offset - (start_offset + 9)
    new_dlsym_offset = dlsym_offset - (start_offset + 16)

    body = b''
    body += b'\xF2\xFF\x25' + struct.pack('<I', new_dlopen_offset)
    body += b'\xF2\xFF\x25' + struct.pack('<I', new_dlsym_offset)

    res = b''
    # jump relative
    res += b'\xeb' + bytes([len(body)])
    res += body
    return res


def find_main(f):
    """
    At offset 27 of _start there is a offset to main()
    """
    e_entry_offset = 16 + 2 + 2 + 4
    e_entry = read_qword(f, e_entry_offset)

    main_offset = read_signed_dword(f, e_entry + 27)

    # 31 is the RIP offset used from e_entry
    return e_entry + main_offset + 31


def find_rela(f, name):
    strtab_offset, symtab_offset, jmprel_offset = (None, None, None)

    # finding the section header
    # got from reading `man elf`
    offset_sh = 16 + 2 + 2 + 4 + 8 + 8
    offset_shentsize = offset_sh + 8 + 4 + 2 + 2 + 2

    e_shoff = read_qword(f, offset_sh)
    e_shentsize = read_word(f, offset_shentsize)

    # passing over dynamic to get the values we need.
    for i in range(0, 64):
        sh_type = read_dword(f, e_shoff + e_shentsize * i + 4)
        dynamic_offset = read_qword(f, e_shoff + e_shentsize * i + 24)
        if sh_type == SHT_DYNAMIC:
            break

    for i in range(0, 1024):
        start = dynamic_offset + i * 16
        end = dynamic_offset + (i + 1) * 16
        dynentry = f[start:end]
        d_tag = read_qword(dynentry, 0)
        d_val = read_qword(dynentry, 8)

        match d_tag:
            case Dynamic.DT_NULL.value:
                break
            case Dynamic.DT_STRTAB.value:
                strtab_offset = d_val
            case Dynamic.DT_SYMTAB.value:
                symtab_offset = d_val
            case Dynamic.DT_JMPREL.value:
                jmprel_offset = d_val

    # passing over the relocations to try and find the name.
    for i in range(0, 1024):
        rela = f[jmprel_offset + i * 24:jmprel_offset + (i + 1) * 24]
        rela_offset = read_qword(rela, 0)
        rela_idx = read_dword(rela, 12)
        # lookup symbol
        st_name = read_dword(f, symtab_offset + rela_idx * 24)
        relname = to_nullbyte(f, strtab_offset + st_name)
        if relname == name:
            return rela_offset


def main():
    f = bytearray(open('/bin/bash', 'rb').read())
    main_offset = find_main(f)
    dlopen_offset = find_rela(f, b'dlopen')
    dlsym_offset = find_rela(f, b'dlsym')
    # prefix our code with wrappers to call the symbols
    print(hex(main_offset), hex(dlopen_offset), hex(dlsym_offset))
    os.system(
        'nasm -f bin ./payload/payload.asm -o payload/payload.bin'
    )
    prefix = create_setup(main_offset, dlopen_offset, dlsym_offset)

    # maybe disable relocs if they tamper with our code.
    with open('payload/payload.bin', 'rb') as pd:
        write_bytes(f, main_offset, prefix + pd.read())

    p = open('new', 'wb')
    p.write(f)
    p.close()
    os.system('chmod +x ./new')


if __name__ == "__main__":
    main()
