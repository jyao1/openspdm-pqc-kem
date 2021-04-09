# This openspdm is a sample implementation for the DMTF [SPDM](https://www.dmtf.org/standards/pmci) specification

## Feature

1) Specification

   The SPDM and secured message follow :

   DSP0274  Security Protocol and Data Model (SPDM) Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.0.pdf) and version [1.1.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.0.pdf))

   DSP0277  Secured Messages using SPDM Specification (version [1.0.0b](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.0.0b.pdf))

   The MCTP and secured MCTP follow :

   DSP0275  Security Protocol and Data Model (SPDM) over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0275_1.0.0.pdf))

   DSP0276  Secured MCTP Messages over MCTP Binding Specification (version [1.0.0a](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.0.0a.pdf))

   The PCI DOE / IDE follow :

   PCI  Data Object Exchange (DOE) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/14143)

   PCI  Component Measurement and Authentication (CMA) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/14236)

   PCI  Integrity and Data Encryption (IDE) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/15149)

2) Both SPDM requester and SPDM responder.

3) Programming Context:

   No heap is required in the SPDM lib.
   No writable global variable is required in the SPDM lib. 

4) Implemented command and response: 

   SPDM 1.0: GET_VERSION, GET_CAPABILITY, NEGOTIATE_ALGORITHM, GET_DIGEST, GET_CERTIFICATE, CHALLENGE, GET_MEASUREMENT.

   SPDM 1.1: KEY_EXCHANGE, FINISH, PSK_EXCHANGE, PSK_FINISH, END_SESSION, HEARTBEAT, KEY_UPDATE, ENCAPSULATED message

5) Cryptographic algorithm support:

   The SPDM lib requires [cryptolib API](https://github.com/jyao1/openspdm/blob/master/libspdm/include/hal/library/cryptlib.h), including random number, symmetric crypto, asymmetric crypto, hash and message authentication code etc.

   Current support algorithm: SHA-2, RSA-SSA/ECDSA, FFDHE/ECDHE, AES_GCM/ChaCha20Poly1305, HMAC.

   An [mbedtls](https://tls.mbed.org/) wrapper is included in [cryptlib_mbedtls](https://github.com/jyao1/openspdm/tree/master/libspdm/os_stub/cryptlib_mbedtls).

   An [openssl](https://www.openssl.org/) wrapper is included in [cryptlib_openssl](https://github.com/jyao1/openspdm/tree/master/libspdm/os_stub/cryptlib_openssl).

6) Execution context:

   Support to build an OS application for spdm_requester_emu and SpdmResponder_emu to trace the communication.

   Support to be included in UEFI host environment [EDKII](https://github.com/tianocore/edk2), such as [edkii_spdm_requester](https://github.com/jyao1/edk2/tree/DeviceSecurity/DeviceSecurityPkg)

   Support to be included in [OpenBMC](https://github.com/openbmc). It is in planning, see [SPDM Integration](https://www.youtube.com/watch?v=PmgXkLJYI-E).

## Document

1) Presentation

   Open Source Firmware Conference 2020 - [openspdm](https://cfp.osfc.io/osfc2020/talk/ECQ88N/)

   Free and Open Source Developers European Meeting 2021 - [openspdm](https://fosdem.org/2021/schedule/event/firmware_uoifaaffsdc/)

2) openspdm library threat model:

   The user guide can be found at [threat_model](https://github.com/jyao1/openspdm/blob/master/libspdm/doc/threat_model.md)

3) openspdm library design:

   The detailed design can be found at [design](https://github.com/jyao1/openspdm/blob/master/libspdm/doc/design.md)

4) openspdm user guide:

   The user guide can be found at [user_guide](https://github.com/jyao1/openspdm/blob/master/libspdm/doc/user_guide.md)


5) PQC Algorithm Summary

   See [PQC algorithm](https://github.com/open-quantum-safe/liboqs/tree/main/docs/algorithms)

| Parameter set  | Security model | Claimed NIST security level | Public key size (bytes) | Secret key size (bytes) | Signature size (bytes) |
| -------------- | -------------- | --------------------------- | ----------------------- | ----------------------- | ---------------------- |
| Dilithium2     | EUF-CMA        | 2                           | 1312                    | 2528                    | 2420                   |
| Dilithium3     | EUF-CMA        | 3                           | 1952                    | 4000                    | 3293                   |
| Dilithium5     | EUF-CMA        | 5                           | 2592                    | 4864                    | 4595                   |
| Dilithium2-AES | EUF-CMA        | 2                           | 1312                    | 2528                    | 2420                   |
| Dilithium3-AES | EUF-CMA        | 3                           | 1952                    | 4000                    | 3293                   |
| Dilithium5-AES | EUF-CMA        | 5                           | 2592                    | 4864                    | 4595                   |
| Falcon-512    | EUF-CMA        | 1                           | 897                     | 1281                    | 690                    |
| Falcon-1024   | EUF-CMA        | 5                           | 1793                    | 2305                    | 1330                   |
| picnic_L1_FS    |     EUF-CMA    |              1              |            33           |            49           |          34036         |
| picnic_L1_UR    |     EUF-CMA    |              1              |            33           |            49           |          53965         |
| picnic_L1_full  |     EUF-CMA    |              1              |            35           |            52           |          32065         |
| picnic_L3_FS    |     EUF-CMA    |              3              |            49           |            73           |          76776         |
| picnic_L3_UR    |     EUF-CMA    |              3              |            49           |            73           |         121849         |
| picnic_L3_full  |     EUF-CMA    |              3              |            49           |            73           |          71183         |
| picnic_L5_FS    |     EUF-CMA    |              5              |            65           |            97           |         132860         |
| picnic_L5_UR    |     EUF-CMA    |              5              |            65           |            97           |         209510         |
| picnic_L5_full  |     EUF-CMA    |              5              |            65           |            97           |         126290         |
| picnic3_L1      |     EUF-CMA    |              1              |            35           |            52           |          14612         |
| picnic3_L3      |     EUF-CMA    |              3              |            49           |            73           |          35028         |
| picnic3_L5      |     EUF-CMA    |              5              |            65           |            97           |          61028         |
| Rainbow-I-Classic          | EUF-CMA        | 1                           | 161600                  | 103648                  | 66                     |
| Rainbow-I-Circumzenithal   | EUF-CMA        | 1                           | 60192                   | 103648                  | 66                     |
| Rainbow-I-Compressed       | EUF-CMA        | 1                           | 60192                   | 64                      | 66                     |
| Rainbow-III-Classic        | EUF-CMA        | 3                           | 882080                  | 626048                  | 164                    |
| Rainbow-III-Circumzenithal | EUF-CMA        | 3                           | 264608                  | 626048                  | 164                    |
| Rainbow-III-Compressed     | EUF-CMA        | 3                           | 264608                  | 64                      | 164                    |
| Rainbow-V-Classic          | EUF-CMA        | 5                           | 1930600                 | 1408736                 | 212                    |
| Rainbow-V-Circumzenithal   | EUF-CMA        | 5                           | 536136                  | 1408736                 | 212                    |
| Rainbow-V-Compressed       | EUF-CMA        | 5                           | 536136                  | 64                      | 212                    |
| SPHINCS+-Haraka-128f-robust   | EUF-CMA        | 1                           | 32                      | 64                      | 16976                  |
| SPHINCS+-Haraka-128f-simple   | EUF-CMA        | 1                           | 32                      | 64                      | 16976                  |
| SPHINCS+-Haraka-128s-robust   | EUF-CMA        | 1                           | 32                      | 64                      | 8080                   |
| SPHINCS+-Haraka-128s-simple   | EUF-CMA        | 1                           | 32                      | 64                      | 8080                   |
| SPHINCS+-Haraka-192f-robust   | EUF-CMA        | 3                           | 48                      | 96                      | 35664                  |
| SPHINCS+-Haraka-192f-simple   | EUF-CMA        | 3                           | 48                      | 96                      | 35664                  |
| SPHINCS+-Haraka-192s-robust   | EUF-CMA        | 3                           | 48                      | 96                      | 17064                  |
| SPHINCS+-Haraka-192s-simple   | EUF-CMA        | 3                           | 48                      | 96                      | 17064                  |
| SPHINCS+-Haraka-256f-robust   | EUF-CMA        | 5                           | 64                      | 128                     | 49216                  |
| SPHINCS+-Haraka-256f-simple   | EUF-CMA        | 5                           | 64                      | 128                     | 49216                  |
| SPHINCS+-Haraka-256s-robust   | EUF-CMA        | 5                           | 64                      | 128                     | 29792                  |
| SPHINCS+-Haraka-256s-simple   | EUF-CMA        | 5                           | 64                      | 128                     | 29792                  |
| SPHINCS+-SHA256-128f-robust   | EUF-CMA        | 1                           | 32                      | 64                      | 16976                  |
| SPHINCS+-SHA256-128f-simple   | EUF-CMA        | 1                           | 32                      | 64                      | 16976                  |
| SPHINCS+-SHA256-128s-robust   | EUF-CMA        | 1                           | 32                      | 64                      | 8080                   |
| SPHINCS+-SHA256-128s-simple   | EUF-CMA        | 1                           | 32                      | 64                      | 8080                   |
| SPHINCS+-SHA256-192f-robust   | EUF-CMA        | 3                           | 48                      | 96                      | 35664                  |
| SPHINCS+-SHA256-192f-simple   | EUF-CMA        | 3                           | 48                      | 96                      | 35664                  |
| SPHINCS+-SHA256-192s-robust   | EUF-CMA        | 3                           | 48                      | 96                      | 17064                  |
| SPHINCS+-SHA256-192s-simple   | EUF-CMA        | 3                           | 48                      | 96                      | 17064                  |
| SPHINCS+-SHA256-256f-robust   | EUF-CMA        | 5                           | 64                      | 128                     | 49216                  |
| SPHINCS+-SHA256-256f-simple   | EUF-CMA        | 5                           | 64                      | 128                     | 49216                  |
| SPHINCS+-SHA256-256s-robust   | EUF-CMA        | 5                           | 64                      | 128                     | 29792                  |
| SPHINCS+-SHA256-256s-simple   | EUF-CMA        | 5                           | 64                      | 128                     | 29792                  |
| SPHINCS+-SHAKE256-128f-robust | EUF-CMA        | 1                           | 32                      | 64                      | 16976                  |
| SPHINCS+-SHAKE256-128f-simple | EUF-CMA        | 1                           | 32                      | 64                      | 16976                  |
| SPHINCS+-SHAKE256-128s-robust | EUF-CMA        | 1                           | 32                      | 64                      | 8080                   |
| SPHINCS+-SHAKE256-128s-simple | EUF-CMA        | 1                           | 32                      | 64                      | 8080                   |
| SPHINCS+-SHAKE256-192f-robust | EUF-CMA        | 3                           | 48                      | 96                      | 35664                  |
| SPHINCS+-SHAKE256-192f-simple | EUF-CMA        | 3                           | 48                      | 96                      | 35664                  |
| SPHINCS+-SHAKE256-192s-robust | EUF-CMA        | 3                           | 48                      | 96                      | 17064                  |
| SPHINCS+-SHAKE256-192s-simple | EUF-CMA        | 3                           | 48                      | 96                      | 17064                  |
| SPHINCS+-SHAKE256-256f-robust | EUF-CMA        | 5                           | 64                      | 128                     | 49216                  |
| SPHINCS+-SHAKE256-256f-simple | EUF-CMA        | 5                           | 64                      | 128                     | 49216                  |
| SPHINCS+-SHAKE256-256s-robust | EUF-CMA        | 5                           | 64                      | 128                     | 29792                  |
| SPHINCS+-SHAKE256-256s-simple | EUF-CMA        | 5                           | 64                      | 128                     | 29792                  |



| Parameter set       | Security model | Claimed NIST security level | Public key size (bytes) | Secret key size (bytes) | Ciphertext size (bytes) | Shared secret size (bytes) |
|---------------------|:--------------:|:---------------------------:|:-----------------------:|:-----------------------:|:-----------------------:|:--------------------------:|
| BIKE1-L1-CPA        |     IND-CPA    |              1              |           2542          |          3110          |           2542          |             32             |
| BIKE1-L3-CPA        |     IND-CPA    |              3              |           4964          |          5788          |           4964          |             32             |
| BIKE1-L1-FO         |     IND-CCA    |              1              |           2946          |          6460          |           2946          |             32             |
| BIKE1-L3-FO         |     IND-CCA    |              3              |           6206          |         13236          |           6206          |             32             |
| Classic-McEliece-348864   | IND-CCA2       | 1                           | 261120                  | 6452                    | 128                     | 32                         |
| Classic-McEliece-348864f  | IND-CCA2       | 1                           | 261120                  | 6452                    | 128                     | 32                         |
| Classic-McEliece-460896   | IND-CCA2       | 3                           | 524160                  | 13568                   | 188                     | 32                         |
| Classic-McEliece-460896f  | IND-CCA2       | 3                           | 524160                  | 13568                   | 188                     | 32                         |
| Classic-McEliece-6688128  | IND-CCA2       | 5                           | 1044992                 | 13892                   | 240                     | 32                         |
| Classic-McEliece-6688128f | IND-CCA2       | 5                           | 1044992                 | 13892                   | 240                     | 32                         |
| Classic-McEliece-6960119  | IND-CCA2       | 5                           | 1047319                 | 13908                   | 226                     | 32                         |
| Classic-McEliece-6960119f | IND-CCA2       | 5                           | 1047319                 | 13908                   | 226                     | 32                         |
| Classic-McEliece-8192128  | IND-CCA2       | 5                           | 1357824                 | 14080                   | 240                     | 32                         |
| Classic-McEliece-8192128f | IND-CCA2       | 5                           | 1357824                 | 14080                   | 240                     | 32                         |
| FrodoKEM-640-AES    |     IND-CCA    |              1              |           9616          |          19888          |           9720          |             16             |
| FrodoKEM-640-SHAKE  |     IND-CCA    |              1              |           9616          |          19888          |           9720          |             16             |
| FrodoKEM-976-AES    |     IND-CCA    |              3              |          15632          |          31296          |          15744          |             24             |
| FrodoKEM-976-SHAKE  |     IND-CCA    |              3              |          15632          |          31296          |          15744          |             24             |
| FrodoKEM-1344-AES   |     IND-CCA    |              5              |          21520          |          43088          |          21632          |             32             |
| FrodoKEM-1344-SHAKE |     IND-CCA    |              5              |          21520          |          43088          |          21632          |             32             |
| HQC-128       | IND-CCA2       | 1                           | 2249                    | 2289                    | 4481                    | 64                         |
| HQC-192       | IND-CCA2       | 3                           | 4522                    | 4562                    | 9026                    | 64                         |
| HQC-256       | IND-CCA2       | 5                           | 7245                    | 7285                    | 14469                   | 64                         |
| Kyber512      | IND-CCA2       | 1                           | 800                     | 1632                    | 768                     | 32                         |
| Kyber768      | IND-CCA2       | 3                           | 1184                    | 2400                    | 1088                    | 32                         |
| Kyber1024     | IND-CCA2       | 5                           | 1568                    | 3168                    | 1568                    | 32                         |
| Kyber512-90s  | IND-CCA2       | 1                           | 800                     | 1632                    | 768                     | 32                         |
| Kyber768-90s  | IND-CCA2       | 1                           | 1184                    | 2400                    | 1088                    | 32                         |
| Kyber1024-90s | IND-CCA2       | 5                           | 1568                    | 3168                    | 1568                    | 32                         |
| NTRU-HPS-2048-509 | IND-CCA2       | 1                           | 699                     | 935                     | 699                     | 32                         |
| NTRU-HPS-2048-677 | IND-CCA2       | 3                           | 930                     | 1234                    | 930                     | 32                         |
| NTRU-HPS-4096-821 | IND-CCA2       | 5                           | 1230                    | 1590                    | 1230                    | 32                         |
| NTRU-HRSS-701     | IND-CCA2       | 3                           | 1138                    | 1450                    | 1138                    | 32                         |
| ntrulpr653    | IND-CCA2       | 2                           | 897                     | 1125                    | 1025                    | 32                         |
| ntrulpr761    | IND-CCA2       | 3                           | 1039                    | 1294                    | 1167                    | 32                         |
| ntrulpr857    | IND-CCA2       | 4                           | 1184                    | 1463                    | 1312                    | 32                         |
| sntrup653     | IND-CCA2       | 2                           | 994                     | 1518                    | 897                     | 32                         |
| sntrup761     | IND-CCA2       | 3                           | 1158                    | 1763                    | 1039                    | 32                         |
| sntrup857     | IND-CCA2       | 4                           | 1322                    | 1999                    | 1184                    | 32                         |
| LightSaber-KEM | IND-CCA2       | 1                           | 672                     | 1568                    | 736                     | 32                         |
| Saber-KEM      | IND-CCA2       | 3                           | 992                     | 2304                    | 1088                    | 32                         |
| FireSaber-KEM  | IND-CCA2       | 5                           | 1312                    | 3040                    | 1472                    | 32                         |
| SIDH-p434            |     IND-CPA    |              1              |           330           |            28           |           330           |             110            |
| SIDH-p434-compressed |     IND-CPA    |              1              |           197           |            28           |           197           |             110            |
| SIDH-p503            |     IND-CPA    |              2              |           378           |            32           |           378           |             126            |
| SIDH-p503-compressed |     IND-CPA    |              2              |           225           |            32           |           225           |             126            |
| SIDH-p610            |     IND-CPA    |              3              |           462           |            39           |           462           |             154            |
| SIDH-p610-compressed |     IND-CPA    |              3              |           274           |            39           |           274           |             154            |
| SIDH-p751            |     IND-CPA    |              5              |           564           |            48           |           564           |             188            |
| SIDH-p751-compressed |     IND-CPA    |              5              |           335           |            48           |           335           |             188            |
| SIKE-p434            |     IND-CCA    |              1              |           330           |           374           |           346           |             16             |
| SIKE-p434-compressed |     IND-CCA    |              1              |           197           |           350           |           236           |             16             |
| SIKE-p503            |     IND-CCA    |              2              |           378           |           434           |           402           |             24             |
| SIKE-p503-compressed |     IND-CCA    |              2              |           225           |           407           |           280           |             24             |
| SIKE-p610            |     IND-CCA    |              3              |           462           |           524           |           486           |             24             |
| SIKE-p610-compressed |     IND-CCA    |              3              |           274           |           491           |           336           |             24             |
| SIKE-p751            |     IND-CCA    |              5              |           564           |           644           |           596           |             32             |
| SIKE-p751-compressed |     IND-CCA    |              5              |           335           |           602           |           410           |             32             |

6) Hybrid Algorithm Summary

See [supported PQC algorithms](https://github.com/open-quantum-safe/openssl#supported-algorithms)

The following quantum-safe algorithms from liboqs are supported (assuming they have been enabled in liboqs):

- **BIKE**: `bike1l1cpa`, `bike1l3cpa`, `bike1l1fo`, `bike1l3fo`
- **CRYSTALS-Kyber**: `kyber512`, `kyber768`, `kyber1024`, `kyber90s512`, `kyber90s768`, `kyber90s1024`
- **FrodoKEM**: `frodo640aes`, `frodo640shake`, `frodo976aes`, `frodo976shake`, `frodo1344aes`, `frodo1344shake`
- **HQC**: `hqc128`, `hqc192`, `hqc256`†
- **NTRU**: `ntru_hps2048509`, `ntru_hps2048677`, `ntru_hps4096821`, `ntru_hrss701`
- **NTRU-Prime**: `ntrulpr653`, `ntrulpr761`, `ntrulpr857`, `sntrup653`, `sntrup761`, `sntrup857`
- **SABER**: `lightsaber`, `saber`, `firesaber`
- **SIDH**: `sidhp434`, `sidhp503`, `sidhp610`, `sidhp751`
- **SIKE**: `sikep434`, `sikep503`, `sikep610`, `sikep751`

If ``<KEX>`` is any of the algorithms listed above, the following hybrid algorithms are supported:

- if `<KEX>` has L1 security, the fork provides the method `p256_<KEX>`, which combine `<KEX>` with ECDH using the P256 curve.
- if `<KEX>` has L3 security, the fork provides the method `p384_<KEX>`, which combines `<KEX>` with ECDH using the P384 curve.
- if `<KEX>` has L5 security, the fork provides the method `p521_<KEX>`, which combines `<KEX>` with ECDH using the P521 curve.

For example, since `kyber768` claims L3 security, the hybrid `p384_kyber768` is available.

- **CRYSTALS-Dilithium**:`dilithium2`\*, `dilithium3`\*, `dilithium5`\*, `dilithium2_aes`\*, `dilithium3_aes`\*, `dilithium5_aes`\*
- **Falcon**:`falcon512`\*, `falcon1024`\*
- **Picnic**:`picnicl1fs`, `picnicl1ur`, `picnicl1full`\*, `picnic3l1`\*, `picnic3l3`, `picnic3l5`
- **Rainbow**:`rainbowIclassic`\*, `rainbowIcircumzenithal`, `rainbowIcompressed`, `rainbowIIIclassic`, `rainbowIIIcircumzenithal`, `rainbowIIIcompressed`, `rainbowVclassic`\*, `rainbowVcircumzenithal`, `rainbowVcompressed`
- **SPHINCS-Haraka**:`sphincsharaka128frobust`\*, `sphincsharaka128fsimple`, `sphincsharaka128srobust`, `sphincsharaka128ssimple`, `sphincsharaka192frobust`, `sphincsharaka192fsimple`, `sphincsharaka192srobust`, `sphincsharaka192ssimple`, `sphincsharaka256frobust`, `sphincsharaka256fsimple`, `sphincsharaka256srobust`, `sphincsharaka256ssimple`
- **SPHINCS-SHA256**:`sphincssha256128frobust`\*, `sphincssha256128fsimple`, `sphincssha256128srobust`, `sphincssha256128ssimple`, `sphincssha256192frobust`, `sphincssha256192fsimple`, `sphincssha256192srobust`, `sphincssha256192ssimple`, `sphincssha256256frobust`, `sphincssha256256fsimple`, `sphincssha256256srobust`, `sphincssha256256ssimple`
- **SPHINCS-SHAKE256**:`sphincsshake256128frobust`\*, `sphincsshake256128fsimple`, `sphincsshake256128srobust`, `sphincsshake256128ssimple`, `sphincsshake256192frobust`, `sphincsshake256192fsimple`, `sphincsshake256192srobust`, `sphincsshake256192ssimple`, `sphincsshake256256frobust`, `sphincsshake256256fsimple`, `sphincsshake256256srobust`, `sphincsshake256256ssimple`
<!--- OQS_TEMPLATE_FRAGMENT_LIST_SIGS_END -->

The following hybrid algorithms are supported; they combine a quantum-safe algorithm listed above with a traditional digital signature algorithm (`<SIG>` is any one of the algorithms listed above):

- if `<SIG>` has L1 security, then the fork provides the methods `rsa3072_<SIG>` and `p256_<SIG>`, which combine `<SIG>` with RSA3072 and with ECDSA using NIST's P256 curve respectively.
- if `<SIG>` has L3 security, the fork provides the method `p384_<SIG>`, which combines `<SIG>` with ECDSA using NIST's P384 curve.
- if `<SIG>` has L5 security, the fork provides the method `p521_<SIG>`, which combines `<SIG>` with ECDSA using NIST's P521 curve.

For example, since `dilithium2` claims L1 security, the hybrids `rsa3072_dilithium2` and `p256_dilithium2` are available.

For hybrid singing, the message to be signed is hashed using the SHA-2 hash function matching the security level of the OQS scheme (SHA256 for L1, SHA384 for L2/L3, SHA512 for L4/L5) before being signed by the classical algorithm. The message to be signed is passed directly to the OQS signature API without hashing.

7) Enabled algorithm summary

* PQC Key Exchange

  See [kem_verify.c](https://github.com/jyao1/openspdm-pqc/blob/master/libspdm/unit_test/test_pqc_crypt/kem_verify.c)

* HYBRID PQC Key Exchange

  Refer to [obj_mac.h](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/include/openssl/obj_mac.h)

| Hybrid Algo                       | Parameter                                                                         |
|-----------------------------------|-----------------------------------------------------------------------------------|
| p256_bike1l1cpa  -                | --dhe SECP_256_R1  --pqc_kem BIKE1_L1_CPA                                         |
| p256_bike1l1fo   -                | --dhe SECP_256_R1  --pqc_kem BIKE1_L1_FO                                          |
| p384_bike1l3cpa  -                | --dhe SECP_384_R1  --pqc_kem BIKE1_L3_CPA                                         |
| p384_bike1l3fo   -                | --dhe SECP_384_R1  --pqc_kem BIKE1_L3_FO                                          |
| p256_frodo640aes                  | --dhe SECP_256_R1  --pqc_kem FRODOKEM_640_AES                                     |
| p256_frodo640shake                | --dhe SECP_256_R1  --pqc_kem FRODOKEM_640_SHAKE                                   |
| p384_frodo976aes    +             | --dhe SECP_384_R1  --pqc_kem FRODOKEM_976_AES                                     |
| p384_frodo976shake  +             | --dhe SECP_384_R1  --pqc_kem FRODOKEM_976_SHAKE                                   |
| p521_frodo1344aes   +             | --dhe SECP_521_R1  --pqc_kem FRODOKEM_1344_AES                                    |
| p521_frodo1344shake +             | --dhe SECP_521_R1  --pqc_kem FRODOKEM_1344_SHAKE                                  |
| p256_hqc128                       | --dhe SECP_256_R1  --pqc_kem HQC_128                                              |
| p384_hqc192                       | --dhe SECP_384_R1  --pqc_kem HQC_192                                              |
| p521_hqc256         +             | --dhe SECP_521_R1  --pqc_kem HQC_256                                              |
| p256_kyber512                     | --dhe SECP_256_R1  --pqc_kem KYBER_512                                            |
| p256_kyber90s512                  | --dhe SECP_256_R1  --pqc_kem KYBER_512_90S                                        |
| p384_kyber768                     | --dhe SECP_384_R1  --pqc_kem KYBER_768                                            |
| p384_kyber90s768                  | --dhe SECP_384_R1  --pqc_kem KYBER_768_90S                                        |
| p521_kyber1024                    | --dhe SECP_521_R1  --pqc_kem KYBER_1024                                           |
| p521_kyber90s1024                 | --dhe SECP_521_R1  --pqc_kem KYBER_1024_90S                                       |
| p256_ntru_hps2048509              | --dhe SECP_256_R1  --pqc_kem NTRU_HPS_2048_509                                    |
| p384_ntru_hps2048677              | --dhe SECP_384_R1  --pqc_kem NTRU_HPS_2048_677                                    |
| p521_ntru_hps4096821              | --dhe SECP_521_R1  --pqc_kem NTRU_HPS_2048_821                                    |
| p384_ntru_hrss701                 | --dhe SECP_384_R1  --pqc_kem NTRU_HRSS_701                                        |
| p256_ntrulpr653                   | --dhe SECP_256_R1  --pqc_kem NTRULPR653                                           |
| p384_ntrulpr761                   | --dhe SECP_384_R1  --pqc_kem NTRULPR761                                           |
| p384_ntrulpr857                   | --dhe SECP_384_R1  --pqc_kem NTRULPR857                                           |
| p256_sntrup653                    | --dhe SECP_256_R1  --pqc_kem SNTRUP653                                            |
| p384_sntrup761                    | --dhe SECP_384_R1  --pqc_kem SNTRUP761                                            |
| p384_sntrup857                    | --dhe SECP_384_R1  --pqc_kem SNTRUP857                                            |
| p256_lightsaber                   | --dhe SECP_256_R1  --pqc_kem LIGHTSABER_KEM                                       |
| p384_saber                        | --dhe SECP_384_R1  --pqc_kem SABER_KEM                                            |
| p521_firesaber                    | --dhe SECP_521_R1  --pqc_kem FIRESABER_KEM                                        |
| p256_sidhp434                     | --dhe SECP_256_R1  --pqc_kem SIDH_P434                                            |
| p256_sidhp503                     | --dhe SECP_256_R1  --pqc_kem SIDH_P503                                            |
| p384_sidhp610                     | --dhe SECP_384_R1  --pqc_kem SIDH_P610                                            |
| p521_sidhp751                     | --dhe SECP_521_R1  --pqc_kem SIDH_P751                                            |
| p256_sikep434                     | --dhe SECP_256_R1  --pqc_kem SIKE_P434                                            |
| p256_sikep503                     | --dhe SECP_256_R1  --pqc_kem SIKE_P510                                            |
| p384_sikep610                     | --dhe SECP_384_R1  --pqc_kem SIKE_P610                                            |
| p521_sikep751                     | --dhe SECP_521_R1  --pqc_kem SIKE_P751                                            |

"-" means unsupported in Windows, and supported in Linux.
"+" means fail in Windows, and succeed in Linux.

* RAW PQC public key mode

  See [sig_verify.c](https://github.com/jyao1/openspdm-pqc/blob/master/libspdm/unit_test/test_pqc_crypt/sig_verify.c)

* HYBRID PQC cert public key mode

  See [hybrid_sig_verify.c](https://github.com/jyao1/openspdm-pqc/blob/master/libspdm/unit_test/test_pqc_crypt/hybrid_sig_verify.c)
  from [obj_mac.h](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/include/openssl/obj_mac.h)

| Hybrid Algo                       | Parameter                                                                                        |
|-----------------------------------|--------------------------------------------------------------------------------------------------|
| rsa3072_dilithium2                | --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig DILITHIUM_2                  |
| rsa3072_dilithium2_aes            | --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig DILITHIUM_2_AES              |
| p256_dilithium2                   | --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig DILITHIUM_2                  |
| p256_dilithium2_aes               | --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig DILITHIUM_2_AES              |
| p384_dilithium3                   | --pqc_pub_key_mode CERT --hash SHA_384 --asym ECDSA_P384  --pqc_sig DILITHIUM_3                  |
| p384_dilithium3_aes               | --pqc_pub_key_mode CERT --hash SHA_384 --asym ECDSA_P384  --pqc_sig DILITHIUM_3_AES              |
| p521_dilithium5                   | --pqc_pub_key_mode CERT --hash SHA_512 --asym ECDSA_P521  --pqc_sig DILITHIUM_5                  |
| p521_dilithium5_aes               | --pqc_pub_key_mode CERT --hash SHA_512 --asym ECDSA_P521  --pqc_sig DILITHIUM_5_AES              |
| rsa3072_falcon512                 | --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig FALCON_512                   |
| p256_falcon512                    | --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig FALCON_512                   |
| p521_falcon1024                   | --pqc_pub_key_mode CERT --hash SHA_512 --asym ECDSA_P521  --pqc_sig FALCON_1024                  |
| rsa3072_picnic3l1     +           | --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig PICNIC3_L1                   |
| rsa3072_picnicl1full              | --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig PICNIC_L1_FULL               |
| p256_picnic3l1        +           | --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig PICNIC3_L1                   |
| p256_picnicl1full     +           | --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig PICNIC_L1_FULL               |
| rsa3072_rainbowIclassic *         | --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig RAINBOW_I_CLASSIC            |
| p256_rainbowIclassic    *         | --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig RAINBOW_I_CLASSIC            |
| p521_rainbowVclassic    *         | --pqc_pub_key_mode CERT --hash SHA_512 --asym ECDSA_P521  --pqc_sig RAINBOW_V_CLASSIC            |
| rsa3072_sphincsharaka128frobust  +| --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig SPHINCS_HARAKA_128F_ROBUST   |
| rsa3072_sphincssha256128frobust  +| --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig SPHINCS_SHA256_128F_ROBUST   |
| rsa3072_sphincsshake256128frobust+| --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig SPHINCS_SHAKE256_128F_ROBUST |
| p256_sphincsharaka128frobust     +| --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig SPHINCS_HARAKA_128F_ROBUST   |
| p256_sphincssha256128frobust     +| --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig SPHINCS_SHA256_128F_ROBUST   |
| p256_sphincsshake256128frobust   +| --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig SPHINCS_SHAKE256_128F_ROBUST |

"*" means unsupported because of large size.
"+" means fail in Windows, and succeed in Linux.

8) Algorithm Stack & Heap usage

  See [PQC Stack Heap Usage](https://github.com/jyao1/CryptoEx/blob/master/QuantumSafePkg/PqcCryptTest/StackHeapUsage.c)

## Prerequisit

### Build Tool

1) [Visual Studio](https://visualstudio.microsoft.com/) (VS2015 or VS2019)

2) [GCC](https://gcc.gnu.org/) (above GCC5)

3) [LLVM](https://llvm.org/) (LLVM9)

   Download and install [LLVM9](http://releases.llvm.org/download.html#9.0.0). Ensure LLVM9 executable directory is in PATH environment variable.

4) [cmake](https://cmake.org/).

### Crypto library

1) [liboqs](https://github.com/open-quantum-safe/liboqs) as PQC crypto library.

   Please download [liboqs](https://github.com/open-quantum-safe/liboqs) and switch to "main" branch "0.5.0" tag.

   Follow the [liboqs+openssl](https://github.com/open-quantum-safe/openssl) build process.
   Install oqs to openspdm-pqc root dir (Parallel to libspdm).
   ```
   mkdir build && cd build
   cmake -GNinja -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX=<some_DIR>/oqs ..
   ninja
   ninja install
   ```

   Copy oqs/oqsconfig.h to libspdm/os_stub/openssllib/include/oqs.

2) [liboqs+openssl](https://github.com/open-quantum-safe/openssl) as crypto library

   Please download [liboqs+openssl](https://github.com/open-quantum-safe/openssl) and switch to "OQS-OpenSSL_1_1_1-stable" branch "OQS-OpenSSL_1_1_1-stable-snapshot-2021-03" tag

   Put openssl under [openssllib](https://github.com/jyao1/openspdm/tree/master/libspdm/os_stub/openssllib)

### Unit Test framework

1) [cmocka](https://cmocka.org/)

   Please download [cmocka-1.1.5](https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz) and unzip it.
   Rename cmocka-1.1.5 to cmocka and put cmocka under [cmockalib](https://github.com/jyao1/openspdm/tree/master/libspdm/unit_test/cmockalib)

## Build

### Windows Build with CMake

   Use x86 command prompt for ARCH=ia32 and x64 command prompt for ARCH=x64. (TOOLCHAIN=VS2019|VS2015|CLANG)
   ```
   cd <libspdm|spdm_emu|spdm_dump>
   mkdir build
   cd build
   cmake -G"NMake Makefiles" -DARCH=<x64|ia32> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=openssl ..
   nmake copy_sample_key
   nmake
   ```

### Linux Build with CMake

   (TOOLCHAIN=GCC|CLANG)
   ```
   cd <libspdm|spdm_emu|spdm_dump>
   mkdir build
   cd build
   cmake -DARCH=<x64|ia32|arm|aarch64|riscv32|riscv64|arc> -DTOOLCHAIN=<toolchain> -DTARGET=<Debug|Release> -DCRYPTO=openssl ..
   make copy_sample_key
   make
   ```

## Run Test

### Run [unit_test](https://github.com/jyao1/openspdm/tree/master/libspdm/unit_test)

   The UnitTest output is at libspdm/build/bin.
   Open one command prompt at output dir to run `test_spdm_requester > NUL` and `test_spdm_responder > NUL`.

   You may see something like:

   <pre>
      [==========] Running 2 test(s).
      [ RUN      ] test_spdm_responder_version_case1
      [       OK ] test_spdm_responder_version_case1
      [ RUN      ] test_spdm_responder_version_case2
      [       OK ] test_spdm_responder_version_case2
      [==========] 2 test(s) run.
      [  PASSED  ] 2 test(s).
   </pre>

### Run [spdm_emu](https://github.com/jyao1/openspdm/tree/master/spdm_emu/spdm_emu)

   The spdm_emu output is at spdm_emu/build/bin.
   Open one command prompt at output dir to run `spdm_responder_emu` and another command prompt to run `spdm_requester_emu`.

   Please refer to [spdm_emu](https://github.com/jyao1/openspdm/blob/master/spdm_emu/doc/spdm_emu.md) for detail.

### [spdm_dump](https://github.com/jyao1/openspdm/tree/master/spdm_dump/spdm_dump) tool

   The tool output is at spdm_dump/build/bin. It can be used to parse the pcap file for offline analysis.

   Please refer to [spdm_dump](https://github.com/jyao1/openspdm/blob/master/spdm_dump/doc/spdm_dump.md) for detail. 

### Other Test

  openspdm also supports other test such as code coverage, fuzzing, symbolic execution, model checker.

  Please refer to [Test](https://github.com/jyao1/openspdm/blob/master/libspdm/doc/test.md) for detail. 

## Feature not implemented yet

1) Please refer to [issues](https://github.com/jyao1/openspdm/issues) for detail

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

