# -*- coding: utf-8 -*-
from saltchannel.util.key_pair import  KeyPair


class CryptoTestData:

    # aSig, bSig generated 2016-08-10 by Frans.
    aSig = KeyPair(sec=bytes.fromhex("55f4d1d198093c84de9ee9a6299e0f6891c2e1d0b369efb592a9e3f169fb0f795529ce8ccf68c0b8ac19d437ab0f5b32723782608e93c6264f184ba152c2357b"),
                   pub=bytes.fromhex("5529ce8ccf68c0b8ac19d437ab0f5b32723782608e93c6264f184ba152c2357b")
                   )

    bSig = KeyPair(sec=bytes.fromhex("7a772fa9014b423300076a2ff646463952f141e2aa8d98263c690c0d72eed52d07e28d4ee32bfdc4b07d41c92193c0c25ee6b3094c6296f373413b373d36168b"),
                   pub=bytes.fromhex("07e28d4ee32bfdc4b07d41c92193c0c25ee6b3094c6296f373413b373d36168b")
                   )


     # aEnc, bEnc are taken from Bernstein's paper at
     # http://cr.yp.to/highspeed/naclcrypto-20090310.pdf.
     # Paper title: Cryptography in NaCl. Here called "Bernstein's paper".
     # They are encryption key pairs (not for signing).
    aEnc = KeyPair(sec=bytes([
                        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
                   ]),
                   pub=bytes([
                        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
                        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
                        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
                        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
                   ])
    )

    bEnc = KeyPair(sec=bytes([
                        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
                        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
                        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
                        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
                   ]),
                   pub=bytes([
                        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
                        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
                        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
                        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,

                   ])
    )

    # cSig, cEnc, dSig, dEnc created 2016-09-16 by Frans.
    cSig = KeyPair(sec=bytes.fromhex("51e47dbb0740d9e05ef30346fe99964cbef11c4e6bacdae19bd957449a574e886b1d0abe9cb6bbf06deae39ac2a083503af8967f19ed05d7e5b698ab7e684803"),
                   pub=bytes.fromhex("6b1d0abe9cb6bbf06deae39ac2a083503af8967f19ed05d7e5b698ab7e684803")
                   )

    cEnc = KeyPair(sec=bytes.fromhex("be3552a308cd05afd2943030a5a582259875d00ab313a7f6d8a8fc6bf3af4732"),
                   pub=bytes.fromhex("f78a7c7040809c6138ed3271d94ee5657b4c81048ca51c7b6f5d3677f6c76a4f")
                   )

    dSig = KeyPair(sec=bytes.fromhex("75d8eb753e555016c111b193327e9004aa90c68d8c0a9620610a7d9bbbbf711ef251ca24196a055ee779c1e7f1722172fa4afecb825b1fde8cd78ff88b8b9df3"),
                   pub=bytes.fromhex("f251ca24196a055ee779c1e7f1722172fa4afecb825b1fde8cd78ff88b8b9df3")
                   )

    dEnc = KeyPair(sec=bytes.fromhex("8903129d8b421a93aaf189e30f3f8691a02ffe638adf9734fda8ac1ce9c510a6"),
                   pub=bytes.fromhex("6230d0df1a5069548447978c107b378ca88179c3799fb99df1007141fc173712")
                   )

    random32a = bytes.fromhex("491cbc6d62351b396c8121a077e739f7764992f30be24a9b25ddedc3d68388c6")
    random16a = bytes.fromhex("d69e8040a8f8a22c39071060211845bd")