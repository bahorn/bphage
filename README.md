# Dumb Dynamic Linking

A weird project that patches an existing binary to do dynamic linking, so glibc
is already setup.
Currently targeting bash, as that calls `dlopen()` and `dlsym()` as part of its
plugin system, so those exist in the PLT.

Currently just a python script that patches main to use libssl to download the
BGGP5 file.

## Details

### Finding `main()`

We read the ELF header, looking to find two sections:
* `.dynstr` so we can check nams.
* `.dynsym`, as it contains the offset to `main`.

We just need to know the start of `.dynstr`, as when we walk through the table
in `.dynsym` it'll give us an offset in `st_name` member of the struct.

### Finding PLT entries.

Looking through the relocations, looking for one that involves the target
symbols.
We get the GOT entry this way.

### Using `dlopen()` and `dlsym()`

I prefixed the payload with psuedo PLT entries that call the symbols we found
relatively.

### An interesting payload

Just using libssl to open a do HTTPS.

### Porting to asm, making smol

todo, using memfd, fexecve trick to execute.
