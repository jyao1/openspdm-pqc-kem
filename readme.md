# This is prototype of post-quantum cryptography version openspdm library.

## Feature

1) PQC Algorithm Summary

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
| HQC-128       | IND-CCA2       | 1                           | 2249                    | 2289                    | 4481                    | 64                         |
| HQC-192       | IND-CCA2       | 3                           | 4522                    | 4562                    | 9026                    | 64                         |
| HQC-256       | IND-CCA2       | 5                           | 7245                    | 7285                    | 14469                   | 64                         |
| Kyber512      | IND-CCA2       | 1                           | 800                     | 1632                    | 768                     | 32                         |
| Kyber768      | IND-CCA2       | 3                           | 1184                    | 2400                    | 1088                    | 32                         |
| Kyber1024     | IND-CCA2       | 5                           | 1568                    | 3168                    | 1568                    | 32                         |
| Kyber512-90s  | IND-CCA2       | 1                           | 800                     | 1632                    | 768                     | 32                         |
| Kyber768-90s  | IND-CCA2       | 1                           | 1184                    | 2400                    | 1088                    | 32                         |
| Kyber1024-90s | IND-CCA2       | 5                           | 1568                    | 3168                    | 1568                    | 32                         |
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

2) Hybrid Algorithm Summary

See [supported PQC algorithms](https://github.com/open-quantum-safe/openssl#supported-algorithms)

The following quantum-safe algorithms from liboqs are supported (assuming they have been enabled in liboqs):

- **BIKE**: `bike1l1cpa`, `bike1l3cpa`, `bike1l1fo`, `bike1l3fo`
- **CRYSTALS-Kyber**: `kyber512`, `kyber768`, `kyber1024`, `kyber90s512`, `kyber90s768`, `kyber90s1024`
- **HQC**: `hqc128`, `hqc192`, `hqc256`†
- **SIDH**: `sidhp434`, `sidhp503`, `sidhp610`, `sidhp751`
- **SIKE**: `sikep434`, `sikep503`, `sikep610`, `sikep751`

If ``<KEX>`` is any of the algorithms listed above, the following hybrid algorithms are supported:

- if `<KEX>` has L1 security, the fork provides the method `p256_<KEX>`, which combine `<KEX>` with ECDH using the P256 curve.
- if `<KEX>` has L3 security, the fork provides the method `p384_<KEX>`, which combines `<KEX>` with ECDH using the P384 curve.
- if `<KEX>` has L5 security, the fork provides the method `p521_<KEX>`, which combines `<KEX>` with ECDH using the P521 curve.

For example, since `kyber768` claims L3 security, the hybrid `p384_kyber768` is available.

- **CRYSTALS-Dilithium**:`dilithium2`\*, `dilithium3`\*, `dilithium5`\*, `dilithium2_aes`\*, `dilithium3_aes`\*, `dilithium5_aes`\*
- **Falcon**:`falcon512`\*, `falcon1024`\*
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

3) Enabled algorithm summary

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
| p256_hqc128                       | --dhe SECP_256_R1  --pqc_kem HQC_128                                              |
| p384_hqc192                       | --dhe SECP_384_R1  --pqc_kem HQC_192                                              |
| p521_hqc256         +             | --dhe SECP_521_R1  --pqc_kem HQC_256                                              |
| p256_kyber512                     | --dhe SECP_256_R1  --pqc_kem KYBER_512                                            |
| p256_kyber90s512                  | --dhe SECP_256_R1  --pqc_kem KYBER_512_90S                                        |
| p384_kyber768                     | --dhe SECP_384_R1  --pqc_kem KYBER_768                                            |
| p384_kyber90s768                  | --dhe SECP_384_R1  --pqc_kem KYBER_768_90S                                        |
| p521_kyber1024                    | --dhe SECP_521_R1  --pqc_kem KYBER_1024                                           |
| p521_kyber90s1024                 | --dhe SECP_521_R1  --pqc_kem KYBER_1024_90S                                       |
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
| rsa3072_sphincsharaka128frobust  +| --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig SPHINCS_HARAKA_128F_ROBUST   |
| rsa3072_sphincssha256128frobust  +| --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig SPHINCS_SHA256_128F_ROBUST   |
| rsa3072_sphincsshake256128frobust+| --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig SPHINCS_SHAKE256_128F_ROBUST |
| p256_sphincsharaka128frobust     +| --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig SPHINCS_HARAKA_128F_ROBUST   |
| p256_sphincssha256128frobust     +| --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig SPHINCS_SHA256_128F_ROBUST   |
| p256_sphincsshake256128frobust   +| --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256  --pqc_sig SPHINCS_SHAKE256_128F_ROBUST |

"*" means unsupported because of large size.
"+" means fail in Windows, and succeed in Linux.

4) Algorithm Stack & Heap usage

  See [PQC Stack Heap Usage](https://github.com/jyao1/CryptoEx/blob/master/QuantumSafePkg/PqcCryptTest/StackHeapUsage.c)

5) Performance

  We collect performance data for a typical SPDM flow:
  * Connection Setup: GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHM
  * Device Authentication: GET_DIGESTS, GET_CERTIFICATE (REQ:CERT_VERIFY), CHALLENGE (RSP:CHAL_SIGN, REQ:CHAL_VERIFY)
  * Secure Session Setup: KEY_EXCHANGE (REQ:KEY_EX_KEM_GEN, RSP:KEY_EX_KEM_ENCAP+KEY_EX_KEM_SIGN, REQ:KEY_EX_KEM_DECAP+KEY_EX_KEM_VERIFY), FINISH

  See table below in microsecond (us) on Intel Core(TM) i7-8665U CPU @ 1.90 GHz.

| Minimal Security Level | Configuration (KEM + SIG) | REQ TOTAL | REQ CERT_VERIFY | REQ CHAL_VERIFY | REQ KEY_EX_KEM_GEN | REQ KEY_EX_KEM_DECAP | REQ KEY_EX_VERIFY | REQ OTHER | RSP TOTAL | RSP CHAL_SIGN | RSP KEY_EX_KEM_ENCAP | RSP KEY_EX_SIGN | RSP OTHER |
|------------------------|---------------------------|-----------|-----------------|-----------------|--------------------|----------------------|------------------|-----------|-----------|---------------|----------------------|-----------------|-----------|
| 1 | p256 + rsa3072 | 4221 | 1122 | 382 | 764 | 798 | 312 | 843 | 27654 | 12345 | 1440 | 11729 | 2140 |
| 1 | p256 + p256 | 6532 | 2444 | 774 | 778 | 834 | 856 | 846 | 7173 | 1153 | 1564 | 1107 | 3349 |
| 1 | p256_Kyber512 + rsa3072_Dilithium2 | 8460 | 2840 | 1036 | 1220 | 1158 | 867 | 1339 | 37754 | 17860 | 1946 | 13312 | 4636 |
| 1 | p256_Kyber512 + p256_Dilithium2 | 10035 | 3523 | 1616 | 1262 | 1100 | 1322 | 1212 | 15643 | 5703 | 1932 | 2613 | 5395 |
| 1 | p256_Kyber512-90s + p256_Dilithium2-AES | 12487 | 4420 | 2246 | 1470 | 1333 | 1846 | 1172 | 22540 | 8431 | 2029 | 5955 | 6125 |
| 1 | p256_Kyber512 + rsa3072_Falcon-512 | 6959 | 2039 | 809 | 1246 | 1092 | 724 | 1049 | 70909 | 35504 | 1886 | 30348 | 3171 |
| 1 | p256_Kyber512 + p256_Falcon-512 | 9979 | 4084 | 1238 | 1286 | 1102 | 1142 | 1127 | 52858 | 24477 | 1868 | 19459 | 7054 |
| 1 | p256_Kyber512 + rsa3072_SPHINCS+-Haraka-128f-robust | 63675 | 1350 | 30122 | 1381 | 1097 | 28365 | 1360 | 1390544 | 693364 | 2346 | 691652 | 3182 |
| 1 | p256_Kyber512 + rsa3072_SPHINCS+-SHA256-128f-robust | 37504 | 1574 | 15799 | 1329 | 1137 | 16252 | 1413 | 742012 | 371809 | 2537 | 364104 | 3562 |
| 1 | p256_Kyber512 + rsa3072_SPHINCS+-SHAKE256-128f-robust | 66093 | 1624 | 29687 | 1281 | 1090 | 30914 | 1497 | 1421568 | 711890 | 2328 | 703388 | 3962 |
| 1 | p256_Kyber512 + p256_SPHINCS+-Haraka-128f-robust | 67132 | 2745 | 30269 | 1652 | 1128 | 30027 | 1311 | 1381466 | 693804 | 1986 | 681308 | 4368 |
| 1 | p256_Kyber512 + p256_SPHINCS+-SHA256-128f-robust | 40367 | 2948 | 16216 | 1348 | 1407 | 16969 | 1479 | 718316 | 356253 | 1934 | 354718 | 5411 |
| 1 | p256_Kyber512 + p256_SPHINCS+-SHAKE256-128f-robust | 70654 | 2875 | 31338 | 1391 | 1117 | 32430 | 1503 | 1421255 | 714763 | 1862 | 699748 | 4882 |
| 3 | p384 + p384 | 12153 | 4125 | 1911 | 1734 | 1817 | 1652 | 914 | 13485 | 2271 | 3323 | 2249 | 5642 |
| 3 | p384_Kyber768 + p384_Dilithium3 | 15988 | 5453 | 2487 | 2246 | 2122 | 2505 | 1175 | 38164 | 11942 | 4236 | 14198 | 7788 |
| 3 | p384_Kyber768-90s + p384_Dilithium3-AES | 20576 | 7898 | 3337 | 2467 | 2472 | 3184 | 1218 | 35742 | 14643 | 3868 | 7618 | 9613 |
| 3 | p384_Kyber768 + p521_Falcon-1024 | 21135 | 8727 | 3488 | 2230 | 2156 | 3468 | 1066 | 102333 | 46571 | 3641 | 42413 | 9708 |
| 5 | p521 + p521 | 19276 | 6494 | 3024 | 3156 | 3054 | 2620 | 928 | 22061 | 4054 | 6741 | 3667 | 7599 |
| 5 | p521_Kyber1024 + p521_Dilithium5 | 26725 | 9418 | 4164 | 3973 | 3808 | 4075 | 1287 | 44528 | 15565 | 7494 | 9018 | 12451 |
| 5 | p521_Kyber1024-90s + p521_Dilithium5-AES | 33128 | 12020 | 5743 | 4331 | 4387 | 5345 | 1302 | 44406 | 13208 | 7288 | 8105 | 15805 |
| 5 | p521_Kyber1024 + p521_Falcon-1024 | 24044 | 8469 | 3166 | 3660 | 4168 | 3337 | 1244 | 103345 | 45607 | 6522 | 39861 | 11355 |

```
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_pub_key_mode RAW --hash SHA_256 --asym RSAPSS_3072
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_pub_key_mode RAW --hash SHA_256 --asym ECDSA_P256
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512 --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig DILITHIUM_2
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512 --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256 --pqc_sig DILITHIUM_2
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512_90S --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256 --pqc_sig DILITHIUM_2_AES
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512 --pqc_pub_key_mode CERT --hash SHA_256 --asym RSAPSS_3072 --pqc_sig FALCON_512
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512 --pqc_pub_key_mode CERT --hash SHA_256 --asym ECDSA_P256 --pqc_sig FALCON_512
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512 --pqc_pub_key_mode RAW --hash SHA_256 --asym RSAPSS_3072 --pqc_sig SPHINCS_HARAKA_128F_ROBUST
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512 --pqc_pub_key_mode RAW --hash SHA_256 --asym RSAPSS_3072 --pqc_sig SPHINCS_SHA256_128F_ROBUST
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512 --pqc_pub_key_mode RAW --hash SHA_256 --asym RSAPSS_3072 --pqc_sig SPHINCS_SHAKE256_128F_ROBUST
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512 --pqc_pub_key_mode RAW --hash SHA_256 --asym ECDSA_P256 --pqc_sig SPHINCS_HARAKA_128F_ROBUST
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512 --pqc_pub_key_mode RAW --hash SHA_256 --asym ECDSA_P256 --pqc_sig SPHINCS_SHA256_128F_ROBUST
  spdm_perf_emu.exe  --dhe SECP_256_R1 --pqc_kem KYBER_512 --pqc_pub_key_mode RAW --hash SHA_256 --asym ECDSA_P256 --pqc_sig SPHINCS_SHAKE256_128F_ROBUST
  spdm_perf_emu.exe  --dhe SECP_384_R1 --pqc_pub_key_mode RAW --hash SHA_384 --asym ECDSA_P384
  spdm_perf_emu.exe  --dhe SECP_384_R1 --pqc_kem KYBER_768 --pqc_pub_key_mode CERT --hash SHA_384 --asym ECDSA_P384 --pqc_sig DILITHIUM_3
  spdm_perf_emu.exe  --dhe SECP_384_R1 --pqc_kem KYBER_768_90S --pqc_pub_key_mode CERT --hash SHA_384 --asym ECDSA_P384 --pqc_sig DILITHIUM_3_AES
  spdm_perf_emu.exe  --dhe SECP_384_R1 --pqc_kem KYBER_768 --pqc_pub_key_mode CERT --hash SHA_384 --asym ECDSA_P521 --pqc_sig FALCON_1024
  spdm_perf_emu.exe  --dhe SECP_521_R1 --pqc_pub_key_mode RAW --hash SHA_512 --asym ECDSA_P521
  spdm_perf_emu.exe  --dhe SECP_521_R1 --pqc_kem KYBER_1024 --pqc_pub_key_mode CERT --hash SHA_512 --asym ECDSA_P521 --pqc_sig DILITHIUM_5
  spdm_perf_emu.exe  --dhe SECP_521_R1 --pqc_kem KYBER_1024_90S --pqc_pub_key_mode CERT --hash SHA_512 --asym ECDSA_P521 --pqc_sig DILITHIUM_5_AES
  spdm_perf_emu.exe  --dhe SECP_521_R1 --pqc_kem KYBER_1024 --pqc_pub_key_mode CERT --hash SHA_512 --asym ECDSA_P521 --pqc_sig FALCON_1024
```

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

