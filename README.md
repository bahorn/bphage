# bphage - amd64 elf with libssl - 618 bytes

This is a BGGP5 entry for ELF that rus on amd64 linux, that actually uses
dynamic linking, just not in the way you expect!

This patches `/bin/bash` in memory and overwrites main with code that will 
`dlopen()` libssl and make calls to it so it can download the BGGP5 file.

See `src/bphage.asm` for the source driven writeup, with explainations of each
part in comments.
Check the commit history to see how I applied optimizations over time, just be
aware I moved files and renamed things which might make things a bit hard to
follow.

```
00000000: 7f45 4c46 eb42 2f62 696e 2f62 6173 6800  .ELF.B/bin/bash.
00000010: 0200 3e00 0100 0000 0100 0000 0500 0000  ..>.............
00000020: 1800 0000 0000 0000 1800 0000 0500 0000  ................
00000030: 0402 0f05 eb22 3800 0100 4000 0000 0000  ....."8...@.....
00000040: 0100 4000 0000 0000 4881 ec00 0050 0048  ..@.....H....P.H
00000050: 8d3d b0ff ffff ebd8 ba00 0050 0054 5e97  .=.........P.T^.
00000060: 930f 058b 4424 2883 c040 837c 0404 0675  ....D$(..@.|...u
00000070: f68b 5c04 188b 341c 8b7c 1c08 83fe 050f  ..\...4..|......
00000080: 44ef 83fe 060f 44c7 83fe 170f 44cf 83c3  D.....D.....D...
00000090: 1085 f675 e08b 7c0c 0c6b ff18 01c7 8b1c  ...u..|..k......
000000a0: 3c01 eb81 3c1c 646c 6f70 440f 4434 0c81  <...<.dlopD.D4..
000000b0: 3c1c 646c 7379 440f 443c 0c83 c118 4d85  <.dlsyD.D<....M.
000000c0: ff74 d24d 85f6 74cd 8b44 2418 505b 83c0  .t.M..t..D$.P[..
000000d0: 1b48 6304 0404 1f01 c353 5a48 01e2 b941  .Hc......SZH...A
000000e0: 0100 0048 8d35 3f00 0000 525f f3a4 83c3  ...H.5?...R_....
000000f0: 0849 29de 83c3 0649 29df 4489 7204 4489  .I)....I).D.r.D.
00000100: 7a0a 31f6 488d 3d04 ffff ffb8 3f01 0000  z.1.H.=.....?...
00000110: 0f05 575b f7da 545e 97b0 010f 0566 41b8  ..W[..T^.....fA.
00000120: 0010 b842 0100 00eb 04eb 0cff 2553 5eeb  ...B........%S^.
00000130: 02ff 2531 d20f 0531 f6ff c648 8d3d 9b00  ..%1...1...H.=..
00000140: 0000 57e8 e3ff ffff 505b 5e56 4883 c60c  ..W.....P[^VH...
00000150: 535f e8da ffff ffff d050 5d5e 5648 83c6  S_.......P]^VH..
00000160: 1e53 5fe8 c9ff ffff 555f ffd0 505d 5e56  .S_.....U_..P]^V
00000170: 4883 c62a 535f e8b6 ffff ff55 5fff d050  H..*S_.....U_..P
00000180: 5d5e 5648 83c6 3e53 5fe8 a3ff ffff 488d  ]^VH..>S_.....H.
00000190: 0dc5 0000 0031 d240 b664 555f ffd0 5e56  .....1.@.dU_..^V
000001a0: 4883 c647 535f e886 ffff ff48 8d35 8400  H..GS_.....H.5..
000001b0: 0000 555f ffd0 5e56 4883 c650 535f e86e  ..U_..^VH..PS_.n
000001c0: ffff ff55 5f50 5d54 5e66 92ff d554 5e92  ...U_P]T^f...T^.
000001d0: ffd5 9254 5eb0 0189 c70f 05eb fe6c 6962  ...T^........lib
000001e0: 7373 6c2e 736f 2e33 0054 4c53 5f63 6c69  ssl.so.3.TLS_cli
000001f0: 656e 745f 6d65 7468 6f64 0053 534c 5f43  ent_method.SSL_C
00000200: 5458 5f6e 6577 0042 494f 5f6e 6577 5f73  TX_new.BIO_new_s
00000210: 736c 5f63 6f6e 6e65 6374 0042 494f 5f63  sl_connect.BIO_c
00000220: 7472 6c00 4249 4f5f 7075 7473 0042 494f  trl.BIO_puts.BIO
00000230: 5f72 6561 6400 4745 5420 2f35 2f35 2048  _read.GET /5/5 H
00000240: 5454 502f 312e 310a 486f 7374 3a62 696e  TTP/1.1.Host:bin
00000250: 6172 792e 676f 6c66 0a0a 6269 6e61 7279  ary.golf..binary
00000260: 2e67 6f6c 663a 3434 3300                 .golf:443.
```

## License

GPL2.
