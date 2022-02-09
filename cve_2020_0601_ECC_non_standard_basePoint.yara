rule cve_2020_0601_ECC_non_standard_basePoint
{
strings:

    $ecc_custom_params = { 06 07 2a 86 48 ce 3d 02 01 30 82 [2] 02 01 01 30 3c 06 07 2a 86 48 ce 3d 01 01 }

    $basePoint_secp384r1 = { 04 aa 87 ca 22 be 8b 05 37 8e b1 c7 1e f3 20 ad 74 6e 1d 3b 62 8b a7 9b 98 59 f7 41 e0 82 54 2a 38 55 02 f2 5d bf 55 29 6c 3a 54 5e 38 72 76 0a b7 36 17 de 4a 96 26 2c 6f 5d 9e 98 bf 92 92 dc 29 f8 f4 1d bd 28 9a 14 7c e9 da 31 13 b5 f0 b8 c0 0a 60 b1 ce 1d 7e 81 9d 7a 43 1d 7c 90 ea 0e 5f}
    $basePoint_secP256r1 = {04 6b 17 d1 f2 e1 2c 42 47 f8 bc e6 e5 63 a4 40 f2 77 03 7d 81 2d eb 33 a0 f4 a1 39 45 d8 98 c2 96 4f e3 42 e2 fe 1a 7f  9b 8e e7 eb 4a 7c 0f 9e 16 2b ce 33 57 6b 31 5e  ce cb b6 40 68 37 bf 51 f5 }
    $basePoint_curve25519 = { 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 09 20 ae 19 a1 b8 a0 86 b4 e0 1e dd 2c 77 48 d1 4c 92 3d 4d 7e 6d 7c 61 b2 29 e9 c5 a2 7e ce d3 d9 }
    $basePoint_nistP256 = { 04 6b 17 d1 f2 e1 2c 42  47 f8 bc e6 e5 63 a4 40 f2 77 03 7d 81 2d eb 33  a0 f4 a1 39 45 d8 98 c2 96 4f e3 42 e2 fe 1a 7f  9b 8e e7 eb 4a 7c 0f 9e 16 2b ce 33 57 6b 31 5e  ce cb b6 40 68 37 bf 51 f5 }
    $basePoint_nistP384 = { 04 aa 87 ca 22 be 8b 05 37 8e b1 c7 1e f3 20 ad 74 6e 1d 3b 62 8b a7 9b  98 59 f7 41 e0 82 54 2a 38 55 02 f2 5d bf 55 29 6c 3a 54 5e 38 72 76 0a b7 36 17 de 4a 96 26 2c 6f 5d 9e 98 bf 92 92 dc 29 f8 f4 1d bd 28 9a 14 7c e9 da 31 13 b5 f0 b8 c0 0a 60 b1 ce 1d 7e 81 9d 7a 43 1d 7c 90 ea 0e 5f }
    $basePoint_brainpoolP256r1 = { 04 8b d2 ae b9 cb 7e 57 cb 2c 4b 48 2f fc 81 b7 af b9 de 27 e1 e3 bd 23 c2 3a 44 53 bd 9a ce 32 62 54 7e f8 35 c3 da c4 fd 97 f8 46 1a 14 61 1d c9 c2 77 45 13 2d ed 8e 54 5c 1d 54 c7 2f 04 69 97 }
    $basePoint_brainpoolP384r1 = { 04 1d 1c 64 f0 68 cf 45 ff a2 a6 3a 81 b7 c1 3f 6b 88 47 a3 e7 7e f1 4f e3 db 7f ca fe 0c bd 10 e8 e8 26 e0 34 36 d6 46 aa ef 87 b2 e2 47 d4 af 1e 8a be 1d 75 20 f9 c2 a4 5c b1 eb 8e 95 cf d5 52 62 b7 0b 29 fe ec 58 64 e1 9c 05 4f f9 91 29 28 0e 46 46 21 77 91 81 11 42 82 03 41 26 3c 53 15}
    $basePoint_brainpoolP512r1 = { 04 81 ae e4 bd d8 2e d9 64 5a 21 32 2e 9c 4c 6a 93 85 ed 9f 70 b5 d9 16 c1 b4 3b 62 ee f4 d0 09 8e ff 3b 1f 78 e2 d0 d4 8d 50 d1 68 7b 93 b9 7d 5f 7c 6d 50 47 40 6a 5e 68 8b 35 22 09 bc b9 f8 22 7d de 38 5d 56 63 32 ec c0 ea bf a9 cf 78 22 fd f2 09 f7 00 24 a5 7b 1a a0 00 c5 5b 88 1f 81 11 b2 dc de 49 4a 5f 48 5e 5b ca 4b d8 8a 27 63 ae d1 ca 2b 2f a8 f0 54 06 78 cd 1e 0f 3a d8 08 92 }
    $basePoint_nistP192 = { 04 18 8d a8 0e b0 30 90 f6 7c bf 20 eb 43 a1 88 00 f4 ff 0a fd 82 ff 10 12 07 19 2b 95 ff c8 da 78 63 10 11 ed 6b 24 cd d5 73 f9 77 a1 1e 79 48 11 }
    $basePoint_nistP224 = { 04 b7 0e 0c bd 6b b4 bf 7f 32 13 90 b9 4a 03 c1 d3 56 c2 11 22 34 32 80 d6 11 5c 1d 21 bd 37 63 88 b5 f7 23 fb 4c 22 df e6 cd 43 75 a0 5a 07 47 64 44 d5 81 99 85 00 7e 34 }
    $basePoint_nistP521 = { 04 00 c6 85 8e 06 b7 04 04 e9 cd 9e 3e cb 66 23 95 b4 42 9c 64 81 39 05 3f b5 21 f8 28 af 60 6b 4d 3d ba a1 4b 5e 77 ef e7 59 28 fe 1d c1 27 a2 ff a8 de 33 48 b3 c1 85 6a 42 9b f9 7e 7e 31 c2 e5 bd 66 01 18 39 29 6a 78 9a 3b c0 04 5c 8a 5f b4 2c 7d 1b d9 98 f5 44 49 57 9b 44 68 17 af bd 17 27 3e 66 2c 97 ee 72 99 5e f4 26 40 c5 50 b9 01 3f ad 07 61 35 3c 70 86 a2 72 c2 40 88 be 94 76 9f d1 66 50 }
    $basePoint_secP160k1 = { 04 3b 4c 38 2c e3 7a a1  92 a4 01 9e 76 30 36 f4 f5 dd 4d 7e bb 93 8c f9  35 31 8f dc ed 6b c2 82 86 53 17 33 c3 f0 3c 4f ee }
    $basePoint_secP160r1 = { 04 4a 96 b5 68 8e f5 73  28 46 64 69 89 68 c3 8b b9 13 cb fc 82 23 a6 28  55 31 68 94 7d 59 dc c9 12 04 23 51 37 7a c5 fb 32 }
    $basePoint_secP160r2 = { 04 52 dc b0 34 29 3a 11 7e 1f 4f f1 1b 30 f7 19 9d 31 44 ce 6d fe af fe f2 e3 31 f2 96 e0 71 fa 0d f9 98 2c fe a7 d4 3f 2e }
    $basePoint_secP192k1 = { 04 db 4f f1 0e c0 57 e9 ae 26 b0 7d 02 80 b7 f4 34 1d a5 d1 b1 ea e0 6c 7d 9b 2f 2f 6d 9c 56 28 a7 84 41 63 d0 15 be 86 34 40 82 aa 88 d9 5e 2f 9d }
    $basePoint_secP192r1 = { 04 18 8d a8 0e b0 30 90 f6 7c bf 20 eb 43 a1 88 00 f4 ff 0a fd 82 ff 10 12 07 19 2b 95 ff c8 da 78 63 10 11 ed 6b 24 cd d5 73 f9 77 a1 1e 79 48 11 }
    $basePoint_secP224k1 = { 04 a1 45 5b 33 4d f0 99 df 30 fc 28 a1 69 a4 67 e9 e4 70 75 a9 0f 7e 65 0e b6 b7 a4 5c 7e 08 9f ed 7f ba 34 42 82 ca fb d6 f7 e3 19 f7 c0 b0 bd 59 e2 ca 4b db 55 6d 61 a5 }
    $basePoint_secP224r1 = { 04 b7 0e 0c bd 6b b4 bf 7f 32 13 90 b9 4a 03 c1 d3 56 c2 11 22 34 32 80 d6 11 5c 1d 21 bd 37 63 88 b5 f7 23 fb 4c 22 df e6 cd 43 75 a0 5a 07 47 64 44 d5 81 99 85 00 7e 34 }
    $basePoint_secP256k1 = { 04 79 be 66 7e f9 dc bb ac 55 a0 62 95 ce 87 0b 07 02 9b fc db 2d ce 28 d9 59 f2 81 5b 16 f8 17 98 48 3a da 77 26 a3 c4 65 5d a4 fb fc 0e 11 08 a8 fd 17 b4 48 a6 85 54 19 9c 47 d0 8f fb 10 d4 b8 }
    $basePoint_secP384r1 = { 04 aa 87 ca 22 be 8b 05 37 8e b1 c7 1e f3 20 ad 74 6e 1d 3b 62 8b a7 9b 98 59 f7 41 e0 82 54 2a 38 55 02 f2 5d bf 55 29 6c 3a 54 5e 38 72 76 0a b7 36 17 de 4a 96 26 2c 6f 5d 9e 98 bf 92 92 dc 29 f8 f4 1d bd 28 9a 14 7c e9 da 31 13 b5 f0 b8 c0 0a 60 b1 ce 1d 7e 81 9d 7a 43 1d 7c 90 ea 0e 5f }
    $basePoint_secP521r1 = { 04 00 c6 85 8e 06 b7 04 04 e9 cd 9e 3e cb 66 23 95 b4 42 9c 64 81 39 05 3f b5 21 f8 28 af 60 6b 4d 3d ba a1 4b 5e 77 ef e7 59 28 fe 1d c1 27 a2 ff a8 de 33 48 b3 c1 85 6a 42 9b f9 7e 7e 31 c2 e5 bd 66 01 18 39 29 6a 78 9a 3b c0 04 5c 8a 5f b4 2c 7d 1b d9 98 f5 44 49 57 9b 44 68 17 af bd 17 27 3e 66 2c 97 ee 72 99 5e f4 26 40 c5 50 b9 01 3f ad 07 61 35 3c 70 86 a2 72 c2 40 88 be 94 76 9f d1 66 50 }
    $basePoint_brainpoolP160r1 = { 04 be d5 af 16 ea 3f 6a 4f 62 93 8c 46 31 eb 5a f7 bd bc db c3 16 67 cb 47 7a 1a 8e c3 38 f9 47 41 66 9c 97 63 16 da 63 21 }
    $basePoint_brainpoolP160t1 = { 04 b1 99 b1 3b 9b 34 ef  c1 39 7e 64 ba eb 05 ac c2 65 ff 23 78 ad d6 71 8b 7c 7c 19 61 f0 99 1b 84 24 43 77 21 52 c9 e0 ad }
    $basePoint_brainpoolP192r1 = { 04 c0 a0 64 7e aa b6 a4 87 53 b0 33 c5 6c b0 f0 90 0a 2f 5c 48 53 37 5f d6 14 b6 90 86 6a bd 5b b8 8b 5f 48 28 c1 49 00 02 e6 77 3f a2 fa 29 9b 8f }
    $basePoint_brainpoolP192t1 = { 04 3a e9 e5 8c 82 f6 3c 30 28 2e 1f e7 bb f4 3f a7 2c 44 6a f6 f4 61 81 29 09 7e 2c 56 67 c2 22 3a 90 2a b5 ca 44 9d 00 84 b7 e5 b3 de 7c cc 01 c9 }
    $basePoint_brainpoolP224r1 = { 04 0d 90 29 ad 2c 7e 5c f4 34 08 23 b2 a8 7d c6 8c 9e 4c e3 17 4c 1e 6e fd ee 12 c0 7d 58 aa 56 f7 72 c0 72 6f 24 c6 b8 9e 4e cd ac 24 35 4b 9e 99 ca a3 f6 d3 76 14 02 cd }
    $basePoint_brainpoolP224t1 = { 04 6a b1 e3 44 ce 25 ff 38 96 42 4e 7f fe 14 76 2e cb 49 f8 92 8a c0 c7 60 29 b4 d5 80 03 74 e9 f5 14 3e 56 8c d2 3f 3f 4d 7c 0d 4b 1e 41 c8 cc 0d 1c 6a bd 5f 1a 46 db 4c }
    $basePoint_brainpoolP256t1 = { 04 a3 e8 eb 3c c1 cf e7 b7 73 22 13 b2 3a 65 61 49 af a1 42 c4 7a af bc 2b 79 a1 91 56 2e 13 05 f4 2d 99 6c 82 34 39 c5 6d 7f 7b 22 e1 46 44 41 7e 69 bc b6 de 39 d0 27 00 1d ab e8 f3 5b 25 c9 be }
    $basePoint_brainpoolP320r1 = { 04 43 bd 7e 9a fb 53 d8 b8 52 89 bc c4 8e e5 bf e6 f2 01 37 d1 0a 08 7e b6 e7 87 1e 2a 10 a5 99 c7 10 af 8d 0d 39 e2 06 11 14 fd d0 55 45 ec 1c c8 ab 40 93 24 7f 77 27 5e 07 43 ff ed 11 71 82 ea a9 c7 78 77 aa ac 6a c7 d3 52 45 d1 69 2e 8e e1 }
    $basePoint_brainpoolP320t1 = { 04 92 5b e9 fb 01 af c6 fb 4d 3e 7d 49 90 01 0f 81 34 08 ab 10 6c 4f 09 cb 7e e0 78 68 cc 13 6f ff 33 57 f6 24 a2 1b ed 52 63 ba 3a 7a 27 48 3e bf 66 71 db ef 7a bb 30 eb ee 08 4e 58 a0 b0 77 ad 42 a5 a0 98 9d 1e e7 1b 1b 9b c0 45 5f b0 d2 c3 }
    $basePoint_brainpoolP384t1 = { 04 18 de 98 b0 2d b9 a3 06 f2 af cd 72 35 f7 2a 81 9b 80 ab 12 eb d6 53 17 24 76 fe cd 46 2a ab ff c4 ff 19 1b 94 6a 5f 54 d8 d0 aa 2f 41 88 08 cc 25 ab 05 69 62 d3 06 51 a1 14 af d2 75 5a d3 36 74 7f 93 47 5b 7a 1f ca 3b 88 f2 b6 a2 08 cc fe 46 94 08 58 4d c2 b2 91 26 75 bf 5b 9e 58 29 28 }
    $basePoint_brainpoolP512t1 = { 04 64 0e ce 5c 12 78 87 17 b9 c1 ba 06 cb c2 a6 fe ba 85 84 24 58 c5 6d de 9d b1 75 8d 39 c0 31 3d 82 ba 51 73 5c db 3e a4 99 aa 77 a7 d6 94 3a 64 f7 a3 f2 5f e2 6f 06 b5 1b aa 26 96 fa 90 35 da 5b 53 4b d5 95 f5 af 0f a2 c8 92 37 6c 84 ac e1 bb 4e 30 19 b7 16 34 c0 11 31 15 9c ae 03 ce e9 d9 93 21 84 be ef 21 6b d7 1d f2 da df 86 a6 27 30 6e cf f9 6d bb 8b ac e1 98 b6 1e 00 f8 b3 32 }
    $basePoint_ec192wapi = { 04 4a d5 f7 04 8d e7 09 ad 51 23 6d e6 5e 4d 4b 48 2c 83 6d c6 e4 10 66 40 02 bb 3a 02 d4 aa ad ac ae 24 81 7a 4c a3 a1 b0 14 b5 27 04 32 db 27 d2 }
    $basePoint_numsP256t1 = { 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0d 7d 0a b4 1e 2a 12 76 db a3 d3 30 b3 9f a0 46 bf be 2a 6d 63 82 4d 30 3f 70 7f 6f b5 33 1c ad ba }
    $basePoint_numsP384t1 = { 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 74 9c da ba 13 6c e9 b6 5b d4 47 17 94 aa 61 9d aa 5c 7b 4c 93 0b ff 8e bd 79 8a 8a e7 53 c6 d7 2f 00 38 60 fe ba ba d5 34 a4 ac f5 fa 7f 5b ee }
    $basePoint_numsP512t1 = { 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 7d 67 e8 41 dc 4c 46 7b 60 50 91 d8 08 69 21 2f 9c eb 12 4b f7 26 97 3f 9f f0 48 77 9e 1d 61 4e 62 ae 2e ce 50 57 b5 da d9 6b 7a 89 7c 1d 72 79 92 61 13 46 38 75 0f 4f 0c b9 10 27 54 3b 1c 5e }
    $basePoint_wtls7 = { 04 52 dc b0 34 29 3a 11 7e 1f 4f f1 1b 30 f7 19 9d 31 44 ce 6d fe af fe f2 e3 31 f2 96 e0 71 fa 0d f9 98 2c fe a7 d4 3f 2e }
    $basePoint_wtls9 = {04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 }
    $basePoint_wtls12 = { 04 b7 0e 0c bd 6b b4 bf 7f 32 13 90 b9 4a 03 c1 d3 56 c2 11 22 34 32 80 d6 11 5c 1d 21 bd 37 63 88 b5 f7 23 fb 4c 22 df e6 cd 43 75 a0 5a 07 47 64 44 d5 81 99 85 00 7e 34 }
    $basePoint_x962P192v1 = { 04 18 8d a8 0e b0 30 90 f6 7c bf 20 eb 43 a1 88 00 f4 ff 0a fd 82 ff 10 12 07 19 2b 95 ff c8 da 78 63 10 11 ed 6b 24 cd d5 73 f9 77 a1 1e 79 48 11 }
    $basePoint_x962P192v2 = { 04 ee a2 ba e7 e1 49 78 42 f2 de 77 69 cf e9 c9 89 c0 72 ad 69 6f 48 03 4a 65 74 d1 1d 69 b6 ec 7a 67 2b b8 2a 08 3d f2 f2 b0 84 7d e9 70 b2 de 15 }
    $basePoint_x962P192v3 = { 04 7d 29 77 81 00 c6 5a 1d a1 78 37 16 58 8d ce 2b 8b 4a ee 8e 22 8f 18 96 38 a9 0f 22 63 73 37 33 4b 49 dc b6 6a 6d c8 f9 97 8a ca 76 48 a9 43 b0 }
    $basePoint_x962P239v1 = { 04 0f fa 96 3c dc a8 81 6c cc 33 b8 64 2b ed f9 05 c3 d3 58 57 3d 3f 27 fb bd 3b 3c b9 aa af 7d eb e8 e4 e9 0a 5d ae 6e 40 54 ca 53 0b a0 46 54 b3 68 18 ce 22 6b 39 fc cb 7b 02 f1 ae }
    $basePoint_x962P239v2 = { 04 38 af 09 d9 87 27 70 51 20 c9 21 bb 5e 9e 26 29 6a 3c dc f2 f3 57 57 a0 ea fd 87 b8 30 e7 5b 01 25 e4 db ea 0e c7 20 6d a0 fc 01 d9 b0 81 32 9f b5 55 de 6e f4 60 23 7d ff 8b e4 ba }
    $basePoint_x962P239v3 = { 04 67 68 ae 8e 18 bb 92 cf cf 00 5c 94 9a a2 c6 d9 48 53 d0 e6 60 bb f8 54 b1 c9 50 5f e9 5a 16 07 e6 89 8f 39 0c 06 bc 1d 55 2b ad 22 6f 3b 6f cf e4 8b 6e 81 84 99 af 18 e3 ed 6c f3 }
    $basePoint_x962P256v1 = { 04 6b 17 d1 f2 e1 2c 42 47 f8 bc e6 e5 63 a4 40 f2 77 03 7d 81 2d eb 33 a0 f4 a1 39 45 d8 98 c2 96 4f e3 42 e2 fe 1a 7f 9b 8e e7 eb 4a 7c 0f 9e 16 2b ce 33 57 6b 31 5e ce cb b6 40 68 37 bf 51 f5 }

condition:
    $ecc_custom_params
    and not any of ($basePoint*)

}
