# bphage - amd64 elf with libssl - 622 bytes

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
00000090: 1085 f675 e08b 340c 8b7c 0c0c 83c1 186b  ...u..4..|.....k
000000a0: ff18 01c7 8b1c 3c01 eb81 3c1c 646c 6f70  ......<...<.dlop
000000b0: 440f 44f6 813c 1c64 6c73 7944 0f44 fe4d  D.D..<.dlsyD.D.M
000000c0: 85ff 74d1 4d85 f674 cc8b 4424 1850 5b83  ..t.M..t..D$.P[.
000000d0: c01b 4863 0404 041f 01c3 535a 4801 e2b9  ..Hc......SZH...
000000e0: 4201 0000 488d 353f 0000 0052 5ff3 a483  B...H.5?...R_...
000000f0: c308 4929 de83 c306 4929 df44 8972 0444  ..I)....I).D.r.D
00000100: 897a 0a31 f648 8d3d 03ff ffff b83f 0100  .z.1.H.=.....?..
00000110: 000f 0557 5bf7 da54 5e97 b001 0f05 6641  ...W[..T^.....fA
00000120: b800 10b8 4201 0000 eb04 eb0c ff25 535e  ....B........%S^
00000130: eb02 ff25 31d2 0f05 31f6 ffc6 488d 3d9c  ...%1...1...H.=.
00000140: 0000 0057 e8e3 ffff ff50 5b5e 5648 83c6  ...W.....P[^VH..
00000150: 0c53 5fe8 daff ffff ffd0 505d 5e56 4883  .S_.......P]^VH.
00000160: c61e 535f e8c9 ffff ff55 5fff d050 5d5e  ..S_.....U_..P]^
00000170: 5648 83c6 2a53 5fe8 b6ff ffff 555f ffd0  VH..*S_.....U_..
00000180: 505d 5e56 4883 c63e 535f e8a3 ffff ff48  P]^VH..>S_.....H
00000190: 8d0d c600 0000 31d2 40b6 6455 5fff d05e  ......1.@.dU_..^
000001a0: 5648 83c6 4753 5fe8 86ff ffff 488d 3585  VH..GS_.....H.5.
000001b0: 0000 0055 5fff d05e 5648 83c6 5053 5fe8  ...U_..^VH..PS_.
000001c0: 6eff ffff 5455 505d 5f5e 6689 eaff d554  n...TUP]_^f....T
000001d0: 5e92 ffd5 9254 5eb0 0189 c70f 05eb fe6c  ^....T^........l
000001e0: 6962 7373 6c2e 736f 2e33 0054 4c53 5f63  ibssl.so.3.TLS_c
000001f0: 6c69 656e 745f 6d65 7468 6f64 0053 534c  lient_method.SSL
00000200: 5f43 5458 5f6e 6577 0042 494f 5f6e 6577  _CTX_new.BIO_new
00000210: 5f73 736c 5f63 6f6e 6e65 6374 0042 494f  _ssl_connect.BIO
00000220: 5f63 7472 6c00 4249 4f5f 7075 7473 0042  _ctrl.BIO_puts.B
00000230: 494f 5f72 6561 6400 4745 5420 2f35 2f35  IO_read.GET /5/5
00000240: 2048 5454 502f 312e 310a 486f 7374 3a62   HTTP/1.1.Host:b
00000250: 696e 6172 792e 676f 6c66 0a0a 6269 6e61  inary.golf..bina
00000260: 7279 2e67 6f6c 663a 3434 3300            ry.golf:443.
```

## License

GPL2.
