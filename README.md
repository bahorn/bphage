# bphage - amd64 elf with libssl - 637 bytes

This is a BGGP5 entry for ELF that rus on amd64 linux, that actually uses
dynamic linking, just not in the way you expect!

This patches /bin/bash in memory and overwrites main with code that will dlopen
libssl and make calls to it so it can download the BGGP5 file.

See src/bphage.asm for the source driven writeup, with explainations of each
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
000000e0: 4e01 0000 488d 3544 0000 0052 5ff3 a483  N...H.5D...R_...
000000f0: c308 4929 de83 c306 4929 df44 8972 0444  ..I)....I).D.r.D
00000100: 897a 0a31 f648 8d3d 03ff ffff b83f 0100  .z.1.H.=.....?..
00000110: 000f 05f7 da54 5e97 b001 0f05 6641 b800  .....T^.....fA..
00000120: 1048 8d35 e7fe ffff b842 0100 00eb 0aeb  .H.5.....B......
00000130: 0cff 2561 6263 64ff 2531 d20f 0555 31f6  ..%abcd.%1...U1.
00000140: ffc6 488d 3da7 0000 00e8 e3ff ffff 505b  ..H.=.........P[
00000150: 488d 35ae 0000 0048 89df e8d8 ffff ffff  H.5....H........
00000160: d050 5d48 8d35 d300 0000 4889 dfe8 c5ff  .P]H.5....H.....
00000170: ffff 555f ffd0 505d 488d 3598 0000 0048  ..U_..P]H.5....H
00000180: 89df e8b0 ffff ff55 5fff d050 5d48 8d35  .......U_..P]H.5
00000190: 6800 0000 4889 dfe8 9bff ffff 488d 0dca  h...H.......H...
000001a0: 0000 0031 d240 b664 555f ffd0 488d 3581  ...1.@.dU_..H.5.
000001b0: 0000 0048 89df e87c ffff ff48 8d35 8700  ...H...|...H.5..
000001c0: 0000 555f ffd0 5455 488d 355c 0000 0048  ..U_..TUH.5\...H
000001d0: 89df e860 ffff ff50 5d5f 5e66 89ea ffd5  ...`...P]_^f....
000001e0: 545e 92ff d592 545e b001 89c7 0f05 ebfe  T^....T^........
000001f0: 6c69 6273 736c 2e73 6f2e 3300 4249 4f5f  libssl.so.3.BIO_
00000200: 6374 726c 0054 4c53 5f63 6c69 656e 745f  ctrl.TLS_client_
00000210: 6d65 7468 6f64 0042 494f 5f6e 6577 5f73  method.BIO_new_s
00000220: 736c 5f63 6f6e 6e65 6374 0042 494f 5f72  sl_connect.BIO_r
00000230: 6561 6400 4249 4f5f 7075 7473 0053 534c  ead.BIO_puts.SSL
00000240: 5f43 5458 5f6e 6577 0047 4554 202f 352f  _CTX_new.GET /5/
00000250: 3520 4854 5450 2f31 2e31 0a48 6f73 743a  5 HTTP/1.1.Host:
00000260: 6269 6e61 7279 2e67 6f6c 660a 0a62 696e  binary.golf..bin
00000270: 6172 792e 676f 6c66 3a34 3433 00         ary.golf:443.
```

## License

GPL2.
