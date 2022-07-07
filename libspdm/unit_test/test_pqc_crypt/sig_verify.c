/** @file
  Application for OQS-SIG Primitives Validation.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "test_pqc_crypt.h"

/*

PQC SIG Testing:
NID: 0x10100, Name: Dilithium2, PubKeySize: 1312, PrivKeySize: 2528, SignatureSize: 2420
NID: 0x10101, Name: Dilithium3, PubKeySize: 1952, PrivKeySize: 4000, SignatureSize: 3293
NID: 0x10102, Name: Dilithium5, PubKeySize: 2592, PrivKeySize: 4864, SignatureSize: 4595
NID: 0x10103, Name: Dilithium2-AES, PubKeySize: 1312, PrivKeySize: 2528, SignatureSize: 2420
NID: 0x10104, Name: Dilithium3-AES, PubKeySize: 1952, PrivKeySize: 4000, SignatureSize: 3293
NID: 0x10105, Name: Dilithium5-AES, PubKeySize: 2592, PrivKeySize: 4864, SignatureSize: 4595
NID: 0x10200, Name: Falcon-512, PubKeySize: 897, PrivKeySize: 1281, SignatureSize: 690
New ... GenKey ... Sign ... (sig_size 661 ...) Verify ... Free ... [PASS]
NID: 0x10201, Name: Falcon-1024, PubKeySize: 1793, PrivKeySize: 2305, SignatureSize: 1330
New ... GenKey ... Sign ... (sig_size 1271 ...) Verify ... Free ... [PASS]
NID: 0x10300, Name: Rainbow-I-Classic, PubKeySize: 161600, PrivKeySize: 103648, SignatureSize: 66
NID: 0x10301, Name: Rainbow-I-Circumzenithal, PubKeySize: 60192, PrivKeySize: 103648, SignatureSize: 66
NID: 0x10302, Name: Rainbow-I-Compressed, PubKeySize: 60192, PrivKeySize: 64, SignatureSize: 66
NID: 0x10303, Name: Rainbow-III-Classic, PubKeySize: 882080, PrivKeySize: 626048, SignatureSize: 164
NID: 0x10304, Name: Rainbow-III-Circumzenithal, PubKeySize: 264608, PrivKeySize: 626048, SignatureSize: 164
NID: 0x10305, Name: Rainbow-III-Compressed, PubKeySize: 264608, PrivKeySize: 64, SignatureSize: 164
NID: 0x10306, Name: Rainbow-V-Classic, PubKeySize: 1930600, PrivKeySize: 1408736, SignatureSize: 212
NID: 0x10307, Name: Rainbow-V-Circumzenithal, PubKeySize: 536136, PrivKeySize: 1408736, SignatureSize: 212
NID: 0x10308, Name: Rainbow-V-Compressed, PubKeySize: 536136, PrivKeySize: 64, SignatureSize: 212
NID: 0x10400, Name: SPHINCS+-Haraka-128f-robust, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x10401, Name: SPHINCS+-Haraka-128f-simple, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x10402, Name: SPHINCS+-Haraka-128s-robust, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x10403, Name: SPHINCS+-Haraka-128s-simple, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x10404, Name: SPHINCS+-Haraka-192f-robust, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x10405, Name: SPHINCS+-Haraka-192f-simple, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x10406, Name: SPHINCS+-Haraka-192s-robust, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x10407, Name: SPHINCS+-Haraka-192s-simple, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x10408, Name: SPHINCS+-Haraka-256f-robust, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x10409, Name: SPHINCS+-Haraka-256f-simple, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x1040a, Name: SPHINCS+-Haraka-256s-robust, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x1040b, Name: SPHINCS+-Haraka-256s-simple, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x1040c, Name: SPHINCS+-SHA256-128f-robust, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x1040d, Name: SPHINCS+-SHA256-128f-simple, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x1040e, Name: SPHINCS+-SHA256-128s-robust, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x1040f, Name: SPHINCS+-SHA256-128s-simple, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x10410, Name: SPHINCS+-SHA256-192f-robust, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x10411, Name: SPHINCS+-SHA256-192f-simple, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x10412, Name: SPHINCS+-SHA256-192s-robust, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x10413, Name: SPHINCS+-SHA256-192s-simple, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x10414, Name: SPHINCS+-SHA256-256f-robust, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x10415, Name: SPHINCS+-SHA256-256f-simple, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x10416, Name: SPHINCS+-SHA256-256s-robust, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x10417, Name: SPHINCS+-SHA256-256s-simple, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x10418, Name: SPHINCS+-SHAKE256-128f-robust, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x10419, Name: SPHINCS+-SHAKE256-128f-simple, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x1041a, Name: SPHINCS+-SHAKE256-128s-robust, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x1041b, Name: SPHINCS+-SHAKE256-128s-simple, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x1041c, Name: SPHINCS+-SHAKE256-192f-robust, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x1041d, Name: SPHINCS+-SHAKE256-192f-simple, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x1041e, Name: SPHINCS+-SHAKE256-192s-robust, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x1041f, Name: SPHINCS+-SHAKE256-192s-simple, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x10420, Name: SPHINCS+-SHAKE256-256f-robust, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x10421, Name: SPHINCS+-SHAKE256-256f-simple, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x10422, Name: SPHINCS+-SHAKE256-256s-robust, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x10423, Name: SPHINCS+-SHAKE256-256s-simple, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x10500, Name: picnic_L1_FS, PubKeySize: 33, PrivKeySize: 49, SignatureSize: 34036
New ... GenKey ... Sign ... (sig_size 32832 ...) Verify ... Free ... [PASS]
NID: 0x10501, Name: picnic_L1_UR, PubKeySize: 33, PrivKeySize: 49, SignatureSize: 53965
New ... GenKey ... Sign ... (sig_size 53961 ...) Verify ... Free ... [PASS]
NID: 0x10502, Name: picnic_L1_full, PubKeySize: 35, PrivKeySize: 52, SignatureSize: 32065
New ... GenKey ... Sign ... (sig_size 31007 ...) Verify ... Free ... [PASS]
NID: 0x10503, Name: picnic_L3_FS, PubKeySize: 49, PrivKeySize: 73, SignatureSize: 76776
New ... GenKey ... Sign ... (sig_size 73988 ...) Verify ... Free ... [PASS]
NID: 0x10504, Name: picnic_L3_UR, PubKeySize: 49, PrivKeySize: 73, SignatureSize: 121849
New ... GenKey ... Sign ... (sig_size 121845 ...) Verify ... Free ... [PASS]
NID: 0x10505, Name: picnic_L3_full, PubKeySize: 49, PrivKeySize: 73, SignatureSize: 71183
New ... GenKey ... Sign ... (sig_size 68731 ...) Verify ... Free ... [PASS]
NID: 0x10506, Name: picnic_L5_FS, PubKeySize: 65, PrivKeySize: 97, SignatureSize: 132860
New ... GenKey ... Sign ... (sig_size 128472 ...) Verify ... Free ... [PASS]
NID: 0x10507, Name: picnic_L5_UR, PubKeySize: 65, PrivKeySize: 97, SignatureSize: 209510
New ... GenKey ... Sign ... (sig_size 209506 ...) Verify ... Free ... [PASS]
NID: 0x10508, Name: picnic_L5_full, PubKeySize: 65, PrivKeySize: 97, SignatureSize: 126290
New ... GenKey ... Sign ... (sig_size 121646 ...) Verify ... Free ... [PASS]
NID: 0x10509, Name: picnic3_L1, PubKeySize: 35, PrivKeySize: 52, SignatureSize: 14612
New ... GenKey ... Sign ... (sig_size 12347 ...) Verify ... Free ... [PASS]
NID: 0x1050a, Name: picnic3_L3, PubKeySize: 49, PrivKeySize: 73, SignatureSize: 35028
New ... GenKey ... Sign ... (sig_size 27800 ...) Verify ... Free ... [PASS]
NID: 0x1050b, Name: picnic3_L5, PubKeySize: 65, PrivKeySize: 97, SignatureSize: 61028
New ... GenKey ... Sign ... (sig_size 47616 ...) Verify ... Free ... [PASS]

*/

uint32   m_pqc_sig_nid[] = {
// DILITHIUM
  PQC_CRYPTO_SIG_NID_DILITHIUM_2,
  PQC_CRYPTO_SIG_NID_DILITHIUM_3,
  PQC_CRYPTO_SIG_NID_DILITHIUM_5,
  PQC_CRYPTO_SIG_NID_DILITHIUM_2_AES,
  PQC_CRYPTO_SIG_NID_DILITHIUM_3_AES,
  PQC_CRYPTO_SIG_NID_DILITHIUM_5_AES,
// FALCON
  PQC_CRYPTO_SIG_NID_FALCON_512,
  PQC_CRYPTO_SIG_NID_FALCON_1024,
// SPHINCS
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_SIMPLE,
};

uint8    m_signature[210000];
uint8    m_public_key[2000000];
uint8    m_private_key[2000000];
char8    file_name[256];

/**
  Validate PQC SIG Interfaces.

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status
validate_pqc_crypt_sig (
  void
  )
{
  uintn    index;
  uintn    nid;
  void     *context;
  boolean  Result;
  uint8    data[8] = "1234567";
  uintn    data_size = sizeof(data);
  uintn    sig_size;

  my_print ("\nPQC SIG Testing:\n");

  for (index = 0; index < ARRAY_SIZE(m_pqc_sig_nid); index++) {
    nid = m_pqc_sig_nid[index];

    my_print_data (
      "NID: 0x%x, ",
      nid
      );
    my_print_data (
      "Name: %s, ",
      (uintn)pqc_get_oqs_sig_name (nid)
      );
    my_print_data (
      "PubKeySize: %d, ",
      pqc_get_oqs_sig_public_key_size(nid)
      );
    my_print_data (
      "PrivKeySize: %d, ",
      pqc_get_oqs_sig_private_key_size(nid)
      );
    my_print_data (
      "SignatureSize: %d\n",
      pqc_get_oqs_sig_signature_size(nid)
      );

    my_print ("New ... ");
    context = pqc_sig_new_by_nid (nid);
    if (context == NULL) {
      my_print ("[FAIL]\n");
      continue;
    }
    my_print ("GenKey ... ");
    Result = pqc_sig_generate_key (context);
    if (!Result) {
      my_print ("[FAIL]\n");
      pqc_sig_free (context);
      continue;
    }

    {
      uintn public_key_size;
      uintn private_key_size;

      public_key_size = pqc_get_oqs_sig_public_key_size (nid);
      ASSERT (public_key_size < sizeof(m_public_key));
      private_key_size = pqc_get_oqs_sig_private_key_size (nid);
      ASSERT (private_key_size < sizeof(m_private_key));
      pqc_sig_get_public_key (context, m_public_key, public_key_size);
      pqc_sig_get_private_key (context, m_private_key, private_key_size);

      strcpy (file_name, "pqc/");
      strcat (file_name, pqc_get_oqs_sig_name(nid));
      strcat (file_name, "_pk.bin");
      write_output_file (file_name, m_public_key, public_key_size);
      strcpy (file_name, "pqc/");
      strcat (file_name, pqc_get_oqs_sig_name(nid));
      strcat (file_name, "_sk.bin");
      write_output_file (file_name, m_private_key, private_key_size);
    }

    my_print ("Sign ... ");
    sig_size = sizeof(m_signature);
    Result = pqc_sig_sign (context, data, data_size, m_signature, &sig_size);
    if (!Result) {
      my_print ("[FAIL]\n");
      pqc_sig_free (context);
      continue;
    }
    if (sig_size != pqc_get_oqs_sig_signature_size(nid)) {
      my_print_data ("(sig_size %d ...) ", sig_size);
    }

    my_print ("Verify ... ");
    Result = pqc_sig_verify (context, data, data_size, m_signature, sig_size);
    if (!Result) {
      my_print ("[FAIL]\n");
      pqc_sig_free (context);
      continue;
    }

    my_print ("Free ... ");
    pqc_sig_free (context);
    my_print ("[PASS]\n");
  }

  return RETURN_SUCCESS;
}