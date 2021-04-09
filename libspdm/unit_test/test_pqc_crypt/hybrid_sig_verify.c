/** @file
  Application for OQS-SIG Primitives Validation.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "test_pqc_crypt.h"

uint8    m_test_signature[210000];

char8 *m_algo_name[] = {
  "rsa3072_dilithium2",
  "rsa3072_dilithium2_aes",
  "p256_dilithium2",
  "p256_dilithium2_aes",
  "p384_dilithium3",
  "p384_dilithium3_aes",
  "p521_dilithium5",
  "p521_dilithium5_aes",

  "rsa3072_falcon512",
  "p256_falcon512",
  "p521_falcon1024",

  "rsa3072_picnic3l1",
  "rsa3072_picnicl1full",
  "p256_picnic3l1",
  "p256_picnicl1full",

  "rsa3072_rainbowIclassic",
  "p256_rainbowIclassic",
  "p521_rainbowVclassic",

  "rsa3072_sphincsharaka128frobust",
  "rsa3072_sphincssha256128frobust",
  "rsa3072_sphincsshake256128frobust",
  "p256_sphincsharaka128frobust",
  "p256_sphincssha256128frobust",
  "p256_sphincsshake256128frobust",
};

/**
  Validate PQC hybrid SIG Interfaces.

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status
validate_pqc_crypt_hybrid_sig (
  void
  )
{
  uintn         index;
  boolean       status;
  uint8         *pub_file_buffer;
  uintn         pub_file_buffer_size;
  void           *pqc_hybrid_pub_key;
  uint8         *priv_file_buffer;
  uintn         priv_file_buffer_size;
  void           *pqc_hybrid_priv_key;
  uintn          sig_size;
  char8          pub_key_file_name[256];
  char8          priv_key_file_name[256];

  my_print ("\nPQC hyrbid SIG Testing:\n");

  for (index = 0; index < ARRAY_SIZE(m_algo_name); index++) {
    my_print_data ("\nalgo: %s\n", (uintn)m_algo_name[index]);

    strcpy (pub_key_file_name, m_algo_name[index]);
    strcat (pub_key_file_name, "/end_requester.cert.der");
    strcpy (priv_key_file_name, m_algo_name[index]);
    strcat (priv_key_file_name, "/end_requester.key");

    status = read_input_file (pub_key_file_name, (void **)&pub_file_buffer, &pub_file_buffer_size);
    if (!status) {
      my_print ("Read pub file fail\n");
      return RETURN_ABORTED;
    }

    status = read_input_file (priv_key_file_name, (void **)&priv_file_buffer, &priv_file_buffer_size);
    if (!status) {
      my_print ("Read priv file fail\n");
      return RETURN_ABORTED;
    }

    pqc_hybrid_pub_key = NULL;
    status    = pqc_hybrid_get_public_key_from_x509 (pub_file_buffer, pub_file_buffer_size, &pqc_hybrid_pub_key);
    if (!status) {
      my_print ("pqc_hybrid_get_public_key_from_x509 fail\n");
      return RETURN_ABORTED;
    } else {
      my_print ("pqc_hybrid_get_public_key_from_x509 ..");
    }

    pqc_hybrid_priv_key = NULL;
    status    = pqc_hybrid_get_private_key_from_pem (priv_file_buffer, priv_file_buffer_size, NULL, &pqc_hybrid_priv_key);
    if (!status) {
      my_print ("pqc_hybrid_get_private_key_from_pem fail\n");
      return RETURN_ABORTED;
    } else {
      my_print ("pqc_hybrid_get_private_key_from_pem ..");
    }

    sig_size = sizeof(m_test_signature);
    status = pqc_hybrid_sign (pqc_hybrid_priv_key, 0, (uint8 *)"test123", sizeof("test123"), m_test_signature, &sig_size);
    if (!status) {
      my_print ("pqc_hybrid_sign FAIL\n");
    } else {
      my_print ("pqc_hybrid_sign PASS ..");
    }

    status = pqc_hybrid_verify (pqc_hybrid_pub_key, 0, (uint8 *)"test123", sizeof("test123"), m_test_signature, sig_size);
    if (!status) {
      my_print ("pqc_hybrid_verify FAIL\n");
    } else {
      my_print ("pqc_hybrid_verify PASS ..\n");
    }

    pqc_hybrid_free (pqc_hybrid_priv_key);
    pqc_hybrid_free (pqc_hybrid_pub_key);

  }

  return RETURN_SUCCESS;
}