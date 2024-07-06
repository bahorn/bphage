# bphage - amd64 elf with libssl - 619 bytes

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
000000d0: 1b48 6304 0404 1f01 c353 5a48 01e2 b942  .Hc......SZH...B
000000e0: 0100 0048 8d35 3f00 0000 525f f3a4 83c3  ...H.5?...R_....
000000f0: 0849 29de 83c3 0649 29df 4489 7204 4489  .I)....I).D.r.D.
00000100: 7a0a 31f6 488d 3d04 ffff ffb8 3f01 0000  z.1.H.=.....?...
00000110: 0f05 575b f7da 545e 97b0 010f 0566 41b8  ..W[..T^.....fA.
00000120: 0010 b842 0100 00eb 04eb 0cff 2553 5eeb  ...B........%S^.
00000130: 02ff 2531 d20f 0531 f6ff c648 8d3d 9c00  ..%1...1...H.=..
00000140: 0000 57e8 e3ff ffff 505b 5e56 4883 c60c  ..W.....P[^VH...
00000150: 535f e8da ffff ffff d050 5d5e 5648 83c6  S_.......P]^VH..
00000160: 1e53 5fe8 c9ff ffff 555f ffd0 505d 5e56  .S_.....U_..P]^V
00000170: 4883 c62a 535f e8b6 ffff ff55 5fff d050  H..*S_.....U_..P
00000180: 5d5e 5648 83c6 3e53 5fe8 a3ff ffff 488d  ]^VH..>S_.....H.
00000190: 0dc6 0000 0031 d240 b664 555f ffd0 5e56  .....1.@.dU_..^V
000001a0: 4883 c647 535f e886 ffff ff48 8d35 8500  H..GS_.....H.5..
000001b0: 0000 555f ffd0 5e56 4883 c650 535f e86e  ..U_..^VH..PS_.n
000001c0: ffff ff54 5550 5d5f 5e66 89ea ffd5 545e  ...TUP]_^f....T^
000001d0: 92ff d592 545e b001 89c7 0f05 ebfe 6c69  ....T^........li
000001e0: 6273 736c 2e73 6f2e 3300 544c 535f 636c  bssl.so.3.TLS_cl
000001f0: 6965 6e74 5f6d 6574 686f 6400 5353 4c5f  ient_method.SSL_
00000200: 4354 585f 6e65 7700 4249 4f5f 6e65 775f  CTX_new.BIO_new_
00000210: 7373 6c5f 636f 6e6e 6563 7400 4249 4f5f  ssl_connect.BIO_
00000220: 6374 726c 0042 494f 5f70 7574 7300 4249  ctrl.BIO_puts.BI
00000230: 4f5f 7265 6164 0047 4554 202f 352f 3520  O_read.GET /5/5
00000240: 4854 5450 2f31 2e31 0a48 6f73 743a 6269  HTTP/1.1.Host:bi
00000250: 6e61 7279 2e67 6f6c 660a 0a62 696e 6172  nary.golf..binar
00000260: 792e 676f 6c66 3a34 3433 00              y.golf:443.
```

## License

GPL2.
