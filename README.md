# bphage - amd64 elf with libssl - 620 bytes

This is a BGGP5 entry for ELF that runs on amd64 linux, that actually uses
dynamic linking, just not in the way you expect!

This patches `/bin/bash` in memory and overwrites main with code that will 
`dlopen()` libssl and make calls to it so it can download the BGGP5 file.

We are a little selective on distros, but modern Ubuntu and Fedora work.
I'd advise using docker to run this if you aren't on those.
* ubuntu:24.04 and ubuntu:22.04 have both been tested.
* fedora:latest has been tested.
* debian:latest requires adjusting an offset, as it seems bash was compiled with
  `-fcf-protection=none`
* ubuntu:20.04 has a different offset to main, and the libssl.so needs to be
  changed to 1.1
* archlinux:latest will not work, as it uses a different type of relocation
  that isn't supported by this.

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
000000d0: 1b48 6304 0404 1f01 c353 5a48 01e2 b943  .Hc......SZH...C
000000e0: 0100 0048 8d35 3f00 0000 525f f3a4 83c3  ...H.5?...R_....
000000f0: 0849 29de 83c3 0649 29df 4489 7204 4489  .I)....I).D.r.D.
00000100: 7a0a 31f6 488d 3d04 ffff ffb8 3f01 0000  z.1.H.=.....?...
00000110: 0f05 575b f7da 545e 97b0 010f 0566 41b8  ..W[..T^.....fA.
00000120: 0010 b842 0100 00eb 04eb 0cff 2553 5eeb  ...B........%S^.
00000130: 02ff 2531 d20f 0531 f6ff c648 8d3d 9d00  ..%1...1...H.=..
00000140: 0000 57e8 e3ff ffff 505b 5e56 535f 4883  ..W.....P[^VS_H.
00000150: c60c e8da ffff ffff d050 5d5e 5653 5f48  .........P]^VS_H
00000160: 83c6 1ee8 c9ff ffff 555f ffd0 505d 5e56  ........U_..P]^V
00000170: 535f 4883 c62a e8b6 ffff ff55 5fff d050  S_H..*.....U_..P
00000180: 5d5e 5653 5f48 83c6 3ee8 a3ff ffff 555f  ]^VS_H..>.....U_
00000190: 488d 0dc5 0000 0031 d240 b664 ffd0 5e56  H......1.@.d..^V
000001a0: 535f 4883 c647 e886 ffff ff48 8d35 8600  S_H..G.....H.5..
000001b0: 0000 555f ffd0 5e56 535f 4883 c650 e86e  ..U_..^VS_H..P.n
000001c0: ffff ff55 5f50 5d54 5e57 5666 92ff d55e  ...U_P]T^WVf...^
000001d0: 5f92 ffd5 9254 5eb0 0189 c70f 05eb fe6c  _....T^........l
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
