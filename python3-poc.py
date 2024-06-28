"""
WIP in progress POC
"""
import struct


SHT_DYNSYM = 0x0b
SHT_STRTAB = 0x03

PAYLOAD = b'\xf3\x0f\x1e\xfa\xeb\xfe'


def get_section_header(f):
    # got from reading `man elf`
    offset_sh = 16 + 2 + 2 + 4 + 8 + 8
    offset_shentsize = offset_sh + 8 + 4 + 2 + 2 + 2
    offset_shnum = offset_shentsize + 2

    e_shoff = struct.unpack('<Q', f[offset_sh:offset_sh + 8])[0]
    e_shentsize = struct.unpack(
        '<H', f[offset_shentsize:offset_shentsize + 2]
    )[0]
    e_shnum = struct.unpack('<H', f[offset_shnum:offset_shnum + 2])[0]

    return (e_shoff, e_shentsize, e_shnum)


def find_section(f, target_type, e_shoff, e_shentsize, e_shnum):
    for i in range(0, e_shnum):
        sh_offset, sh_size, sh_entsize, sh_type = find_section_idx(
            f, i, e_shoff, e_shentsize, e_shnum
        )
        if target_type == sh_type:
            return (sh_offset, sh_size, sh_entsize)


def find_section_idx(f, idx, e_shoff, e_shentsize, e_shnum):
    shent = f[e_shoff + e_shentsize * idx:e_shoff + e_shentsize * (idx + 1)]
    offset_sh_type = 4
    sh_type = struct.unpack(
        '<I', shent[offset_sh_type:offset_sh_type + 4]
    )[0]
    # now lets search the symbols
    offset_sh_offset = 4 + 4 + 8 + 8
    offset_sh_size = offset_sh_offset + 8
    offset_sh_entsize = offset_sh_size + 8 + 4 + 4 + 8
    sh_offset = struct.unpack(
        '<Q', shent[offset_sh_offset:offset_sh_offset + 8]
    )[0]
    sh_size = struct.unpack(
        '<Q', shent[offset_sh_size:offset_sh_size + 8]
    )[0]
    sh_entsize = struct.unpack(
        '<Q', shent[offset_sh_entsize:offset_sh_entsize + 8]
    )[0]
    return (sh_offset, sh_size, sh_entsize, sh_type)


def get_symbols(
        f, target_st_name, strtab_offset, sh_offset, sh_size, sh_entsize):
    for i in range(0, sh_size // sh_entsize):
        symtab = f[
            sh_offset + sh_entsize * i: sh_offset + sh_entsize * (i + 1)
        ]
        offset_st_name = 0
        offset_st_value = 4 + 1 + 1 + 2
        offset_st_size = 4 + 1 + 1 + 2 + 8
        st_name = struct.unpack(
            '<I', symtab[offset_st_name:offset_st_name + 4]
        )[0]
        st_value = struct.unpack(
            '<Q', symtab[offset_st_value:offset_st_value + 8]
        )[0]
        st_size = struct.unpack(
            '<Q', symtab[offset_st_size:offset_st_size + 8]
        )[0]

        name = f[
            strtab_offset + st_name:
            strtab_offset + st_name + len(target_st_name)
        ]
        if target_st_name == name:
            return (st_value, st_size)


def main():
    f = open('/bin/bash', 'rb').read()
    e_shoff, e_shentsize, e_shnum = get_section_header(f)
    strtab_offset, _, _ = find_section(
        f, SHT_STRTAB, e_shoff, e_shentsize, e_shnum
    )

    sh_offset, sh_size, sh_entsize = find_section(
        f, SHT_DYNSYM, e_shoff, e_shentsize, e_shnum
    )
    target_st_name = b"main"
    st_value, st_size = get_symbols(
        f, target_st_name, strtab_offset, sh_offset, sh_size, sh_entsize
    )
    n = bytearray(f)
    n[st_value:st_value + len(PAYLOAD)] = PAYLOAD
    p = open('new', 'wb')
    p.write(n)
    p.close()
    print(st_value, st_size)


if __name__ == "__main__":
    main()
