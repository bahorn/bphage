# bphage - amd64 elf with libssl - 634 bytes

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
000000e0: 4e01 0000 488d 3541 0000 0052 5ff3 a483  N...H.5A...R_...
000000f0: c308 4929 de83 c306 4929 df44 8972 0444  ..I)....I).D.r.D
00000100: 897a 0a31 f648 8d3d 03ff ffff b83f 0100  .z.1.H.=.....?..
00000110: 000f 0557 5bf7 da54 5e97 b001 0f05 6641  ...W[..T^.....fA
00000120: b800 1053 5eb8 4201 0000 eb0a eb0c ff25  ...S^.B........%
00000130: 6162 6364 ff25 31d2 0f05 5531 f6ff c648  abcd.%1...U1...H
00000140: 8d3d a700 0000 e8e3 ffff ff50 5b48 8d35  .=.........P[H.5
00000150: ae00 0000 4889 dfe8 d8ff ffff ffd0 505d  ....H.........P]
00000160: 488d 35d3 0000 0048 89df e8c5 ffff ff55  H.5....H.......U
00000170: 5fff d050 5d48 8d35 9800 0000 4889 dfe8  _..P]H.5....H...
00000180: b0ff ffff 555f ffd0 505d 488d 3568 0000  ....U_..P]H.5h..
00000190: 0048 89df e89b ffff ff48 8d0d ca00 0000  .H.......H......
000001a0: 31d2 40b6 6455 5fff d048 8d35 8100 0000  1.@.dU_..H.5....
000001b0: 4889 dfe8 7cff ffff 488d 3587 0000 0055  H...|...H.5....U
000001c0: 5fff d054 5548 8d35 5c00 0000 4889 dfe8  _..TUH.5\...H...
000001d0: 60ff ffff 505d 5f5e 6689 eaff d554 5e92  `...P]_^f....T^.
000001e0: ffd5 9254 5eb0 0189 c70f 05eb fe6c 6962  ...T^........lib
000001f0: 7373 6c2e 736f 2e33 0042 494f 5f63 7472  ssl.so.3.BIO_ctr
00000200: 6c00 544c 535f 636c 6965 6e74 5f6d 6574  l.TLS_client_met
00000210: 686f 6400 4249 4f5f 6e65 775f 7373 6c5f  hod.BIO_new_ssl_
00000220: 636f 6e6e 6563 7400 4249 4f5f 7265 6164  connect.BIO_read
00000230: 0042 494f 5f70 7574 7300 5353 4c5f 4354  .BIO_puts.SSL_CT
00000240: 585f 6e65 7700 4745 5420 2f35 2f35 2048  X_new.GET /5/5 H
00000250: 5454 502f 312e 310a 486f 7374 3a62 696e  TTP/1.1.Host:bin
00000260: 6172 792e 676f 6c66 0a0a 6269 6e61 7279  ary.golf..binary
00000270: 2e67 6f6c 663a 3434 3300                 .golf:443.
```

## License

GPL2.
