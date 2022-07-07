/** @file
  Application for OQS-KEM Primitives Validation.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "test_pqc_crypt.h"

/*

PQC KEM Testing:
NID: 0x20100, Name: BIKE1-L1-CPA, PubKeySize: 2542, PrivKeySize: 3110, CipherTextSize: 2542, SharedKeySize: 32
NID: 0x20101, Name: BIKE1-L3-CPA, PubKeySize: 4964, PrivKeySize: 5788, CipherTextSize: 4964, SharedKeySize: 32
NID: 0x20102, Name: BIKE1-L1-FO, PubKeySize: 2946, PrivKeySize: 6460, CipherTextSize: 2946, SharedKeySize: 32
NID: 0x20103, Name: BIKE1-L3-FO, PubKeySize: 6206, PrivKeySize: 13236, CipherTextSize: 6206, SharedKeySize: 32
NID: 0x20200, Name: Classic-McEliece-348864, PubKeySize: 261120, PrivKeySize: 6452, CipherTextSize: 128, SharedKeySize: 32
NID: 0x20201, Name: Classic-McEliece-348864f, PubKeySize: 261120, PrivKeySize: 6452, CipherTextSize: 128, SharedKeySize: 32
NID: 0x20202, Name: Classic-McEliece-460896, PubKeySize: 524160, PrivKeySize: 13568, CipherTextSize: 188, SharedKeySize: 32
NID: 0x20203, Name: Classic-McEliece-460896f, PubKeySize: 524160, PrivKeySize: 13568, CipherTextSize: 188, SharedKeySize: 32
NID: 0x20204, Name: Classic-McEliece-6688128, PubKeySize: 1044992, PrivKeySize: 13892, CipherTextSize: 240, SharedKeySize: 32
NID: 0x20205, Name: Classic-McEliece-6688128f, PubKeySize: 1044992, PrivKeySize: 13892, CipherTextSize: 240, SharedKeySize: 32
NID: 0x20206, Name: Classic-McEliece-6960119, PubKeySize: 1047319, PrivKeySize: 13908, CipherTextSize: 226, SharedKeySize: 32
NID: 0x20207, Name: Classic-McEliece-6960119f, PubKeySize: 1047319, PrivKeySize: 13908, CipherTextSize: 226, SharedKeySize: 32
NID: 0x20208, Name: Classic-McEliece-8192128, PubKeySize: 1357824, PrivKeySize: 14080, CipherTextSize: 240, SharedKeySize: 32
NID: 0x20209, Name: Classic-McEliece-8192128f, PubKeySize: 1357824, PrivKeySize: 14080, CipherTextSize: 240, SharedKeySize: 32
NID: 0x20300, Name: HQC-128, PubKeySize: 2249, PrivKeySize: 2289, CipherTextSize: 4481, SharedKeySize: 64
NID: 0x20301, Name: HQC-192, PubKeySize: 4522, PrivKeySize: 4562, CipherTextSize: 9026, SharedKeySize: 64
NID: 0x20302, Name: HQC-256, PubKeySize: 7245, PrivKeySize: 7285, CipherTextSize: 14469, SharedKeySize: 64
NID: 0x20400, Name: Kyber512, PubKeySize: 800, PrivKeySize: 1632, CipherTextSize: 768, SharedKeySize: 32
NID: 0x20401, Name: Kyber768, PubKeySize: 1184, PrivKeySize: 2400, CipherTextSize: 1088, SharedKeySize: 32
NID: 0x20402, Name: Kyber1024, PubKeySize: 1568, PrivKeySize: 3168, CipherTextSize: 1568, SharedKeySize: 32
NID: 0x20403, Name: Kyber512-90s, PubKeySize: 800, PrivKeySize: 1632, CipherTextSize: 768, SharedKeySize: 32
NID: 0x20404, Name: Kyber768-90s, PubKeySize: 1184, PrivKeySize: 2400, CipherTextSize: 1088, SharedKeySize: 32
NID: 0x20405, Name: Kyber1024-90s, PubKeySize: 1568, PrivKeySize: 3168, CipherTextSize: 1568, SharedKeySize: 32
NID: 0x20500, Name: NTRU-HPS-2048-509, PubKeySize: 699, PrivKeySize: 935, CipherTextSize: 699, SharedKeySize: 32
NID: 0x20501, Name: NTRU-HPS-2048-677, PubKeySize: 930, PrivKeySize: 1234, CipherTextSize: 930, SharedKeySize: 32
NID: 0x20502, Name: NTRU-HPS-4096-821, PubKeySize: 1230, PrivKeySize: 1590, CipherTextSize: 1230, SharedKeySize: 32
NID: 0x20503, Name: NTRU-HRSS-701, PubKeySize: 1138, PrivKeySize: 1450, CipherTextSize: 1138, SharedKeySize: 32
NID: 0x20600, Name: ntrulpr653, PubKeySize: 897, PrivKeySize: 1125, CipherTextSize: 1025, SharedKeySize: 32
NID: 0x20601, Name: ntrulpr761, PubKeySize: 1039, PrivKeySize: 1294, CipherTextSize: 1167, SharedKeySize: 32
NID: 0x20602, Name: ntrulpr857, PubKeySize: 1184, PrivKeySize: 1463, CipherTextSize: 1312, SharedKeySize: 32
NID: 0x20603, Name: sntrup653, PubKeySize: 994, PrivKeySize: 1518, CipherTextSize: 897, SharedKeySize: 32
NID: 0x20604, Name: sntrup761, PubKeySize: 1158, PrivKeySize: 1763, CipherTextSize: 1039, SharedKeySize: 32
NID: 0x20605, Name: sntrup857, PubKeySize: 1322, PrivKeySize: 1999, CipherTextSize: 1184, SharedKeySize: 32
NID: 0x20700, Name: LightSaber-KEM, PubKeySize: 672, PrivKeySize: 1568, CipherTextSize: 736, SharedKeySize: 32
NID: 0x20701, Name: Saber-KEM, PubKeySize: 992, PrivKeySize: 2304, CipherTextSize: 1088, SharedKeySize: 32
NID: 0x20702, Name: FireSaber-KEM, PubKeySize: 1312, PrivKeySize: 3040, CipherTextSize: 1472, SharedKeySize: 32
NID: 0x20800, Name: FrodoKEM-640-AES, PubKeySize: 9616, PrivKeySize: 19888, CipherTextSize: 9720, SharedKeySize: 16
NID: 0x20801, Name: FrodoKEM-640-SHAKE, PubKeySize: 9616, PrivKeySize: 19888, CipherTextSize: 9720, SharedKeySize: 16
NID: 0x20802, Name: FrodoKEM-976-AES, PubKeySize: 15632, PrivKeySize: 31296, CipherTextSize: 15744, SharedKeySize: 24
NID: 0x20803, Name: FrodoKEM-976-SHAKE, PubKeySize: 15632, PrivKeySize: 31296, CipherTextSize: 15744, SharedKeySize: 24
NID: 0x20804, Name: FrodoKEM-1344-AES, PubKeySize: 21520, PrivKeySize: 43088, CipherTextSize: 21632, SharedKeySize: 32
NID: 0x20805, Name: FrodoKEM-1344-SHAKE, PubKeySize: 21520, PrivKeySize: 43088, CipherTextSize: 21632, SharedKeySize: 32
NID: 0x20900, Name: SIDH-p434, PubKeySize: 330, PrivKeySize: 28, CipherTextSize: 330, SharedKeySize: 110
NID: 0x20901, Name: SIDH-p434-compressed, PubKeySize: 197, PrivKeySize: 28, CipherTextSize: 197, SharedKeySize: 110
NID: 0x20902, Name: SIDH-p503, PubKeySize: 378, PrivKeySize: 32, CipherTextSize: 378, SharedKeySize: 126
NID: 0x20903, Name: SIDH-p503-compressed, PubKeySize: 225, PrivKeySize: 32, CipherTextSize: 225, SharedKeySize: 126
NID: 0x20904, Name: SIDH-p610, PubKeySize: 462, PrivKeySize: 39, CipherTextSize: 462, SharedKeySize: 154
NID: 0x20905, Name: SIDH-p610-compressed, PubKeySize: 274, PrivKeySize: 39, CipherTextSize: 274, SharedKeySize: 154
NID: 0x20906, Name: SIDH-p751, PubKeySize: 564, PrivKeySize: 48, CipherTextSize: 564, SharedKeySize: 188
NID: 0x20907, Name: SIDH-p751-compressed, PubKeySize: 335, PrivKeySize: 48, CipherTextSize: 335, SharedKeySize: 188
NID: 0x20908, Name: SIKE-p434, PubKeySize: 330, PrivKeySize: 374, CipherTextSize: 346, SharedKeySize: 16
NID: 0x20909, Name: SIKE-p434-compressed, PubKeySize: 197, PrivKeySize: 350, CipherTextSize: 236, SharedKeySize: 16
NID: 0x2090a, Name: SIKE-p503, PubKeySize: 378, PrivKeySize: 434, CipherTextSize: 402, SharedKeySize: 24
NID: 0x2090b, Name: SIKE-p503-compressed, PubKeySize: 225, PrivKeySize: 407, CipherTextSize: 280, SharedKeySize: 24
NID: 0x2090c, Name: SIKE-p610, PubKeySize: 462, PrivKeySize: 524, CipherTextSize: 486, SharedKeySize: 24
NID: 0x2090d, Name: SIKE-p610-compressed, PubKeySize: 274, PrivKeySize: 491, CipherTextSize: 336, SharedKeySize: 24
NID: 0x2090e, Name: SIKE-p751, PubKeySize: 564, PrivKeySize: 644, CipherTextSize: 596, SharedKeySize: 32
NID: 0x2090f, Name: SIKE-p751-compressed, PubKeySize: 335, PrivKeySize: 602, CipherTextSize: 410, SharedKeySize: 32

*/

uint32   m_pqc_kem_nid[] = {
// BIKE
#if defined OQS_ENABLE_KEM_BIKE
  PQC_CRYPTO_KEM_NID_BIKE1_L1_CPA,
  PQC_CRYPTO_KEM_NID_BIKE1_L3_CPA,
  PQC_CRYPTO_KEM_NID_BIKE1_L1_FO,
  PQC_CRYPTO_KEM_NID_BIKE1_L3_FO,
#endif
// CLASSIC_MCELIECE
#if !defined(_MSC_EXTENSIONS)
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864F,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896F,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128F,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119F,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128F,
#endif
// HQC
  PQC_CRYPTO_KEM_NID_HQC_128,
  PQC_CRYPTO_KEM_NID_HQC_192,
  PQC_CRYPTO_KEM_NID_HQC_256,
// KYBER
  PQC_CRYPTO_KEM_NID_KYBER_512,
  PQC_CRYPTO_KEM_NID_KYBER_768,
  PQC_CRYPTO_KEM_NID_KYBER_1024,
  PQC_CRYPTO_KEM_NID_KYBER_512_90S,
  PQC_CRYPTO_KEM_NID_KYBER_768_90S,
  PQC_CRYPTO_KEM_NID_KYBER_1024_90S,
// SIKE
  PQC_CRYPTO_KEM_NID_SIDH_P434,
  PQC_CRYPTO_KEM_NID_SIDH_P434_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIDH_P503,
  PQC_CRYPTO_KEM_NID_SIDH_P503_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIDH_P610,
  PQC_CRYPTO_KEM_NID_SIDH_P610_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIDH_P751,
  PQC_CRYPTO_KEM_NID_SIDH_P751_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIKE_P434,
  PQC_CRYPTO_KEM_NID_SIKE_P434_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIKE_P503,
  PQC_CRYPTO_KEM_NID_SIKE_P503_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIKE_P610,
  PQC_CRYPTO_KEM_NID_SIKE_P610_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIKE_P751,
  PQC_CRYPTO_KEM_NID_SIKE_P751_COMPRESSED,
};

uint8    m_shared_key1[200];
uint8    m_shared_key2[200];
uint8    m_cipher_text2[22000];
uint8    m_pub_key1[1400000];

/**
  Validate PQC KEM Interfaces.

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status
validate_pqc_crypt_kem (
  void
  )
{
  uintn    index;
  uintn    nid;
  void     *context1;
  void     *context2;
  boolean  result;
  uintn    pub_key1_size;
  uintn    cipher_text2_size;
  uintn    shared_key1_size;
  uintn    shared_key2_size;

  my_print ("\nPQC KEM Testing:\n");

  for (index = 0; index < ARRAY_SIZE(m_pqc_kem_nid); index++) {
    nid = m_pqc_kem_nid[index];

    my_print_data (
      "NID: 0x%x, ",
      nid
      );
    my_print_data (
      "Name: %s, ",
      (uintn)pqc_get_oqs_kem_name (nid)
      );
    my_print_data (
      "PubKeySize: %d, ",
      pqc_get_oqs_kem_public_key_size(nid)
      );
    my_print_data (
      "PrivKeySize: %d, ",
      pqc_get_oqs_kem_private_key_size(nid)
      );
    my_print_data (
      "CipherTextSize: %d, ",
      pqc_get_oqs_kem_cipher_text_size(nid)
      );
    my_print_data (
      "SharedKeySize: %d\n",
      pqc_get_oqs_kem_shared_key_size(nid)
      );

    // Alice 1
    my_print ("New1 ... ");
    context1 = pqc_kem_new_by_nid (nid);
    if (context1 == NULL) {
      my_print ("[FAIL]\n");
      continue;
    }
    my_print ("GenKey1 ... ");
    result = pqc_kem_generate_key (context1);
    if (!result) {
      my_print ("[FAIL]\n");
      pqc_kem_free (context1);
      continue;
    }
    my_print ("GetPub1 ... ");
    pub_key1_size = sizeof(m_pub_key1);
    result = pqc_kem_get_public_key (context1, m_pub_key1, &pub_key1_size);
    if (!result) {
      my_print ("[FAIL]\n");
      pqc_kem_free (context1);
      continue;
    }
    if (pub_key1_size != pqc_get_oqs_kem_public_key_size(nid)) {
      my_print_data ("(pub_key_size %d ...) ", pub_key1_size);
    }

    // Bob 1
    my_print ("New2 ... ");
    context2 = pqc_kem_new_by_nid (nid);
    if (context2 == NULL) {
      my_print ("[FAIL]\n");
      pqc_kem_free (context1);
      continue;
    }
    my_print ("pqc_kem_encap2 ... ");
    shared_key2_size = sizeof(m_shared_key2);
    cipher_text2_size = sizeof(m_cipher_text2);
    result = pqc_kem_encap (context2, m_pub_key1, pub_key1_size, m_shared_key2, &shared_key2_size, m_cipher_text2, &cipher_text2_size);
    if (!result) {
      my_print ("[FAIL]\n");
      pqc_kem_free (context1);
      pqc_kem_free (context2);
      continue;
    }
    if (cipher_text2_size != pqc_get_oqs_kem_cipher_text_size(nid)) {
      my_print_data ("(cipher_text_size %d ...) ", cipher_text2_size);
    }
    if (shared_key2_size != pqc_get_oqs_kem_shared_key_size(nid)) {
      my_print_data ("(shared_key_size %d ...) ", shared_key2_size);
    }

    // Alice 2
    my_print ("pqc_kem_decap1 ... ");
    shared_key1_size = sizeof(m_shared_key1);
    result = pqc_kem_decap (context1, m_shared_key1, &shared_key1_size, m_cipher_text2, cipher_text2_size);
    if (!result) {
      my_print ("[FAIL]\n");
      pqc_kem_free (context1);
      pqc_kem_free (context2);
      continue;
    }

    // Verify both
    my_print ("Verify Size ... ");
    if (shared_key1_size != shared_key2_size) {
      my_print ("[FAIL]\n");
      pqc_kem_free (context1);
      pqc_kem_free (context2);
      continue;
    }
    my_print ("Verify Data ... ");
    if (compare_mem (m_shared_key1, m_shared_key2, shared_key2_size) != 0) {
      my_print ("[FAIL]\n");
      pqc_kem_free (context1);
      pqc_kem_free (context2);
      continue;
    }

    my_print ("Free1 ... ");
    pqc_kem_free (context1);
    my_print ("Free2 ... ");
    pqc_kem_free (context2);
    my_print ("[PASS]\n");
  }

  return RETURN_SUCCESS;
}