# Dumb Dynamic Linking

A weird project that patches an existing binary to do dynamic linking, so glibc
is already setup.
Currently targeting bash, as that calls `dlopen()` and `dlsym()` as part of its
plugin system, so those exist in the PLT.

Currently just a python script that patches in `\xeb\xfe` to `main()`.

## Details

### Finding `main()`

We read the ELF header, looking to find two sections:
* `.dynstr` so we can check nams.
* `.dynsym`, as it contains the offset to `main`.

We just need to know the start of `.dynstr`, as when we walk through the table
in `.dynsym` it'll give us an offset in `st_name` member of the struct.

### Finding PLT entries.

todo

### Using `dlopen()` and `dlsym()`

todo

### An interesting payload

todo, just libssl to open a do HTTPS.

### Porting to C, making smol

todo, using memfd, fexecve trick to execute.
