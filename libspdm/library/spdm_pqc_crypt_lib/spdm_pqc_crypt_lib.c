/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <library/spdm_pqc_crypt_lib.h>
#include <library/pqc_crypt_lib.h>

typedef struct {
  uintn nid;
  uint8 byte_index;
  uint8 byte;
} spdm_pqc_algo_table_t;

spdm_pqc_algo_table_t m_spdm_pqc_sig_algo_name_table[] = {
  {PQC_CRYPTO_SIG_NID_PICNIC_L1_FS,                 SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN,      SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L1_FS},
  {PQC_CRYPTO_SIG_NID_PICNIC_L1_UR,                 SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN,      SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L1_UR},
  {PQC_CRYPTO_SIG_NID_PICNIC_L1_FULL,               SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN,      SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L1_FULL},
  {PQC_CRYPTO_SIG_NID_PICNIC_L3_FS,                 SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN,      SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L3_FS},
  {PQC_CRYPTO_SIG_NID_PICNIC_L3_UR,                 SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN,      SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L3_UR},
  {PQC_CRYPTO_SIG_NID_PICNIC_L3_FULL,               SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN,      SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L3_FULL},
  {PQC_CRYPTO_SIG_NID_PICNIC_L5_FS,                 SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN,      SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L5_FS},
  {PQC_CRYPTO_SIG_NID_PICNIC_L5_UR,                 SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN,      SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L5_UR},
  {PQC_CRYPTO_SIG_NID_PICNIC_L5_FULL,               SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN + 1,  SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L5_FULL >> 8},
  {PQC_CRYPTO_SIG_NID_PICNIC3_L1,                   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN + 1,  SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC3_L1 >> 8},
  {PQC_CRYPTO_SIG_NID_PICNIC3_L3,                   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN + 1,  SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC3_L3 >> 8},
  {PQC_CRYPTO_SIG_NID_PICNIC3_L5,                   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_INDEX_BEGIN + 1,  SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC3_L5 >> 8},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_2,                  SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_INDEX_BEGIN,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_2},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_3,                  SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_INDEX_BEGIN,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_3},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_5,                  SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_INDEX_BEGIN,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_5},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_2_AES,              SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_INDEX_BEGIN,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_2_AES},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_3_AES,              SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_INDEX_BEGIN,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_3_AES},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_5_AES,              SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_INDEX_BEGIN,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_5_AES},
  {PQC_CRYPTO_SIG_NID_FALCON_512,                   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_FALCON_INDEX_BEGIN,      SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_FALCON_512},
  {PQC_CRYPTO_SIG_NID_FALCON_1024,                  SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_FALCON_INDEX_BEGIN,      SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_FALCON_1024},
  {PQC_CRYPTO_SIG_NID_RAINBOW_I_CLASSIC,            SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_I_CLASSIC},
  {PQC_CRYPTO_SIG_NID_RAINBOW_I_CIRCUMZENITHAL,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_I_CIRCUMZENITHAL},
  {PQC_CRYPTO_SIG_NID_RAINBOW_I_COMPRESSED,         SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_I_COMPRESSED},
  {PQC_CRYPTO_SIG_NID_RAINBOW_III_CLASSIC,          SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_III_CLASSIC},
  {PQC_CRYPTO_SIG_NID_RAINBOW_III_CIRCUMZENITHAL,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_III_CIRCUMZENITHAL},
  {PQC_CRYPTO_SIG_NID_RAINBOW_III_COMPRESSED,       SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_III_COMPRESSED},
  {PQC_CRYPTO_SIG_NID_RAINBOW_V_CLASSIC,            SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_V_CLASSIC},
  {PQC_CRYPTO_SIG_NID_RAINBOW_V_CIRCUMZENITHAL,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_V_CIRCUMZENITHAL},
  {PQC_CRYPTO_SIG_NID_RAINBOW_V_COMPRESSED,         SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_V_COMPRESSED >> 8},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_128F_ROBUST},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_128F_SIMPLE},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_128S_ROBUST},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_128S_SIMPLE},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_192F_ROBUST},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_192F_SIMPLE},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_192S_ROBUST},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_192S_SIMPLE},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_256F_ROBUST >> 8},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_256F_SIMPLE >> 8},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_256S_ROBUST >> 8},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_256S_SIMPLE >> 8},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_128F_ROBUST >> 8},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_128F_SIMPLE >> 8},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_128S_ROBUST >> 8},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_128S_SIMPLE >> 8},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 2, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_192F_ROBUST >> 16},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 2, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_192F_SIMPLE >> 16},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 2, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_192S_ROBUST >> 16},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 2, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_192S_SIMPLE >> 16},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 2, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_256F_ROBUST >> 16},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 2, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_256F_SIMPLE >> 16},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_ROBUST,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 2, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_256S_ROBUST >> 16},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_SIMPLE,   SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 2, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_256S_SIMPLE >> 16},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_ROBUST, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 3, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_128F_ROBUST >> 24},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_SIMPLE, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 3, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_128F_SIMPLE >> 24},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_ROBUST, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 3, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_128S_ROBUST >> 24},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_SIMPLE, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 3, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_128S_SIMPLE >> 24},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_ROBUST, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 3, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_192F_ROBUST >> 24},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_SIMPLE, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 3, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_192F_SIMPLE >> 24},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_ROBUST, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 3, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_192S_ROBUST >> 24},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_SIMPLE, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 3, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_192S_SIMPLE >> 24},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_ROBUST, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 4, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_256F_ROBUST >> 32},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_SIMPLE, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 4, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_256F_SIMPLE >> 32},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_ROBUST, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 4, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_256S_ROBUST >> 32},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_SIMPLE, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_INDEX_BEGIN + 4, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_256S_SIMPLE >> 32},
};


spdm_pqc_algo_table_t m_spdm_pqc_kem_algo_name_table[] = {
  {PQC_CRYPTO_KEM_NID_BIKE1_L1_CPA,              SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_BIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_BIKE1_L1_CPA},
  {PQC_CRYPTO_KEM_NID_BIKE1_L3_CPA,              SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_BIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_BIKE1_L3_CPA},
  {PQC_CRYPTO_KEM_NID_BIKE1_L1_FO,               SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_BIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_BIKE1_L1_FO},
  {PQC_CRYPTO_KEM_NID_BIKE1_L3_FO ,              SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_BIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_BIKE1_L3_FO},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864,   SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_348864},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864F,  SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_348864F},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896,   SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_460896},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896F,  SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_460896F},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128,  SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_6688128},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128F, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_6688128F},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119,  SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_6960119},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119F, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_INDEX_BEGIN,     SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_6960119F},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128,  SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_8192128 >> 8},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128F, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_INDEX_BEGIN + 1, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_8192128F >> 8},
  {PQC_CRYPTO_KEM_NID_HQC_128,                   SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_HQC_INDEX_BEGIN,                  SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_HQC_128},
  {PQC_CRYPTO_KEM_NID_HQC_192,                   SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_HQC_INDEX_BEGIN,                  SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_HQC_192},
  {PQC_CRYPTO_KEM_NID_HQC_256,                   SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_HQC_INDEX_BEGIN,                  SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_HQC_256},
  {PQC_CRYPTO_KEM_NID_KYBER_512,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_INDEX_BEGIN,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_512},
  {PQC_CRYPTO_KEM_NID_KYBER_768,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_INDEX_BEGIN,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_768},
  {PQC_CRYPTO_KEM_NID_KYBER_1024,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_INDEX_BEGIN,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_1024},
  {PQC_CRYPTO_KEM_NID_KYBER_512_90S,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_INDEX_BEGIN,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_512_90S},
  {PQC_CRYPTO_KEM_NID_KYBER_768_90S,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_INDEX_BEGIN,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_768_90S},
  {PQC_CRYPTO_KEM_NID_KYBER_1024_90S,            SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_INDEX_BEGIN,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_1024_90S},
  {PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_509,         SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRU_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRU_HPS_2048_509},
  {PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_677,         SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRU_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRU_HPS_2048_677},
  {PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_821,         SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRU_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRU_HPS_2048_821},
  {PQC_CRYPTO_KEM_NID_NTRU_HRSS_701,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRU_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRU_HRSS_701},
  {PQC_CRYPTO_KEM_NID_NTRULPR653,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRUPRIME_INDEX_BEGIN,            SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRULPR653},
  {PQC_CRYPTO_KEM_NID_NTRULPR761,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRUPRIME_INDEX_BEGIN,            SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRULPR761},
  {PQC_CRYPTO_KEM_NID_NTRULPR857,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRUPRIME_INDEX_BEGIN,            SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRULPR857},
  {PQC_CRYPTO_KEM_NID_SNTRUP653,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRUPRIME_INDEX_BEGIN,            SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SNTRUP653},
  {PQC_CRYPTO_KEM_NID_SNTRUP761,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRUPRIME_INDEX_BEGIN,            SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SNTRUP761},
  {PQC_CRYPTO_KEM_NID_SNTRUP857,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRUPRIME_INDEX_BEGIN,            SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SNTRUP857},
  {PQC_CRYPTO_KEM_NID_LIGHTSABER_KEM,            SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SABER_INDEX_BEGIN,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_LIGHTSABER_KEM},
  {PQC_CRYPTO_KEM_NID_SABER_KEM,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SABER_INDEX_BEGIN,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SABER_KEM},
  {PQC_CRYPTO_KEM_NID_FIRESABER_KEM,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SABER_INDEX_BEGIN,                SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FIRESABER_KEM},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_640_AES,          SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_INDEX_BEGIN,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_640_AES},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_640_SHAKE,        SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_INDEX_BEGIN,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_640_SHAKE},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_976_AES,          SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_INDEX_BEGIN,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_976_AES},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_976_SHAKE,        SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_INDEX_BEGIN,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_976_SHAKE},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_1344_AES,         SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_INDEX_BEGIN,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_1344_AES},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_1344_SHAKE,       SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_INDEX_BEGIN,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_1344_SHAKE},
  {PQC_CRYPTO_KEM_NID_SIDH_P434,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIDH_P434},
  {PQC_CRYPTO_KEM_NID_SIDH_P434_COMPRESSED,      SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIDH_P434_COMPRESSED},
  {PQC_CRYPTO_KEM_NID_SIDH_P503,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIDH_P503},
  {PQC_CRYPTO_KEM_NID_SIDH_P503_COMPRESSED,      SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIDH_P503_COMPRESSED},
  {PQC_CRYPTO_KEM_NID_SIDH_P610,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIDH_P610},
  {PQC_CRYPTO_KEM_NID_SIDH_P610_COMPRESSED,      SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIDH_P610_COMPRESSED},
  {PQC_CRYPTO_KEM_NID_SIDH_P751,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIDH_P751},
  {PQC_CRYPTO_KEM_NID_SIDH_P751_COMPRESSED,      SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIDH_P751_COMPRESSED},
  {PQC_CRYPTO_KEM_NID_SIKE_P434,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN + 1,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_P434 >> 8},
  {PQC_CRYPTO_KEM_NID_SIKE_P434_COMPRESSED,      SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN + 1,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_P434_COMPRESSED >> 8},
  {PQC_CRYPTO_KEM_NID_SIKE_P503,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN + 1,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_P503 >> 8},
  {PQC_CRYPTO_KEM_NID_SIKE_P503_COMPRESSED,      SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN + 1,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_P503_COMPRESSED >> 8},
  {PQC_CRYPTO_KEM_NID_SIKE_P610,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN + 1,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_P610 >> 8},
  {PQC_CRYPTO_KEM_NID_SIKE_P610_COMPRESSED,      SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN + 1,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_P610_COMPRESSED >> 8},
  {PQC_CRYPTO_KEM_NID_SIKE_P751,                 SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN + 1,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_P751 >> 8},
  {PQC_CRYPTO_KEM_NID_SIKE_P751_COMPRESSED,      SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_INDEX_BEGIN + 1,             SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIKE_P751_COMPRESSED >> 8},
};

boolean
spdm_get_single_bit (
  IN   pqc_algo_t     pqc_sig_algo,
  OUT  uint8        *byte_index,
  OUT  uint8        *bit_index
  )
{
  uint8  index;
  uint8  byte;
  uint8  bit;
  
  byte = 0;
  for (index = 0; index < sizeof(pqc_algo_t); index++) {
    if (pqc_sig_algo[index] != 0) {
      if (byte == 0) {
        byte = pqc_sig_algo[index];
        *byte_index = index;
      } else {
        // dup byte set
        ASSERT(FALSE);
        return FALSE;
      }
    }
  }
  if (byte == 0) {
    // no byte set
    //ASSERT(FALSE);
    return FALSE;
  }

  bit = 0xFF;
  for (index = 0; index < 8; index++) {
    if ((byte & (1 << index)) != 0) {
      if (bit == 0xFF) {
        bit = index;
        *bit_index = index;
      } else {
        // dup bit set
        ASSERT(FALSE);
        return FALSE;
      }
    }
  }
  if (bit == 0xFF) {
    // no bit set
    ASSERT(FALSE);
    return FALSE;
  }

  return TRUE;
}

spdm_pqc_algo_table_t *
spdm_get_pqc_algo_entry (
  IN   pqc_algo_t             pqc_sig_algo,
  IN   spdm_pqc_algo_table_t  *table,
  IN   uintn                table_count
  )
{
  uint8   byte_index;
  uint8   bit_index;
  boolean result;
  uint8   index;

  result = spdm_get_single_bit (pqc_sig_algo, &byte_index, &bit_index);
  if (!result) {
    return NULL;
  }

  for (index = 0; index < table_count; index++) {
    if ((table[index].byte_index == byte_index) && (table[index].byte == (1 << bit_index))) {
      return &table[index];
    }
  }
  return NULL;
}

void
spdm_get_pqc_algo_from_nid (
  IN  uintn            nid,
  OUT pqc_algo_t       pqc_algo
  )
{
  uintn  index;

  zero_mem (pqc_algo, sizeof(pqc_algo_t));
  for (index = 0; index < ARRAY_SIZE(m_spdm_pqc_sig_algo_name_table); index++) {
    if (m_spdm_pqc_sig_algo_name_table[index].nid == nid) {
      pqc_algo[m_spdm_pqc_sig_algo_name_table[index].byte_index] = m_spdm_pqc_sig_algo_name_table[index].byte;
      return ;
    }
  }
  for (index = 0; index < ARRAY_SIZE(m_spdm_pqc_kem_algo_name_table); index++) {
    if (m_spdm_pqc_kem_algo_name_table[index].nid == nid) {
      pqc_algo[m_spdm_pqc_kem_algo_name_table[index].byte_index] = m_spdm_pqc_kem_algo_name_table[index].byte;
      return ;
    }
  }
}

void
spdm_pqc_algo_and (
  IN pqc_algo_t        pqc_algo_1,
  IN pqc_algo_t        pqc_algo_2,
  OUT pqc_algo_t       pqc_algo
  )
{
  uintn index;
  for (index = 0; index < sizeof(pqc_algo_t); index++) {
    pqc_algo[index] = pqc_algo_1[index] & pqc_algo_2[index];
  }
}

void
spdm_pqc_algo_or (
  IN pqc_algo_t        pqc_algo_1,
  IN pqc_algo_t        pqc_algo_2,
  OUT pqc_algo_t       pqc_algo
  )
{
  uintn index;
  for (index = 0; index < sizeof(pqc_algo_t); index++) {
    pqc_algo[index] = pqc_algo_1[index] | pqc_algo_2[index];
  }
}

boolean
spdm_pqc_algo_is_zero (
  IN pqc_algo_t        pqc_algo
  )
{
  uintn index;
  for (index = 0; index < sizeof(pqc_algo_t); index++) {
    if (pqc_algo[index] != 0) {
      return FALSE;
    }
  }
  return TRUE;
}

spdm_pqc_algo_table_t *
spdm_get_pqc_sig_algo_entry (
  IN   pqc_algo_t     pqc_sig_algo
  )
{
  return spdm_get_pqc_algo_entry (pqc_sig_algo, m_spdm_pqc_sig_algo_name_table, ARRAY_SIZE(m_spdm_pqc_sig_algo_name_table));
}

spdm_pqc_algo_table_t *
spdm_get_pqc_kem_algo_entry (
  IN   pqc_algo_t     pqc_kem_algo
  )
{
  return spdm_get_pqc_algo_entry (pqc_kem_algo, m_spdm_pqc_kem_algo_name_table, ARRAY_SIZE(m_spdm_pqc_kem_algo_name_table));
}

uintn
spdm_get_pqc_sig_nid (
  IN   pqc_algo_t     pqc_sig_algo
  )
{
  spdm_pqc_algo_table_t  *algo_entry;

  algo_entry = spdm_get_pqc_sig_algo_entry (pqc_sig_algo);
  if (algo_entry == NULL) {
    return 0;
  }
  return algo_entry->nid;
}

char8 *
spdm_get_pqc_sig_name (
  IN   pqc_algo_t     pqc_sig_algo
  )
{
  uintn  nid;

  nid = spdm_get_pqc_sig_nid (pqc_sig_algo);
  if (nid == 0) {
    return NULL;
  }
  return pqc_get_oqs_sig_name (nid);
}

uintn
spdm_get_pqc_kem_nid (
  IN   pqc_algo_t     pqc_kem_algo
  )
{
  spdm_pqc_algo_table_t  *algo_entry;

  algo_entry = spdm_get_pqc_kem_algo_entry (pqc_kem_algo);
  if (algo_entry == NULL) {
    return 0;
  }
  return algo_entry->nid;
}

char8 *
spdm_get_pqc_kem_name (
  IN   pqc_algo_t     pqc_kem_algo
  )
{
  uintn  nid;

  nid = spdm_get_pqc_kem_nid (pqc_kem_algo);
  if (nid == 0) {
    return NULL;
  }
  return pqc_get_oqs_kem_name (nid);
}

/**
  This function returns the SPDM pqc_sig_algo algorithm size.

  @param  pqc_sig_algo                   SPDM pqc_sig_algo

  @return SPDM pqc_sig_algo algorithm size.
**/
uint32
spdm_get_pqc_sig_public_key_size (
  IN   pqc_algo_t     pqc_sig_algo
  )
{
  spdm_pqc_algo_table_t  *algo_entry;

  algo_entry = spdm_get_pqc_sig_algo_entry (pqc_sig_algo);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)pqc_get_oqs_sig_public_key_size (algo_entry->nid);
}

/**
  This function returns the SPDM pqc_sig_algo algorithm size.

  @param  pqc_sig_algo                   SPDM pqc_sig_algo

  @return SPDM pqc_sig_algo algorithm size.
**/
uint32
spdm_get_pqc_sig_signature_size (
  IN   pqc_algo_t     pqc_sig_algo
  )
{
  spdm_pqc_algo_table_t  *algo_entry;

  algo_entry = spdm_get_pqc_sig_algo_entry (pqc_sig_algo);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)pqc_get_oqs_sig_signature_size (algo_entry->nid);
}

/**
  Retrieve the PQC Public Key from raw data,
  based upon negotiated PQC SIG algorithm.

  @param  pqc_sig_algo                   SPDM pqc_sig_algo
  @param  raw_data                      Pointer to raw data buffer to hold the public key.
  @param  raw_data_size                  Size of the raw data buffer in bytes.
  @param  context                      Pointer to new-generated PQC SIG context which contain the retrieved public key component.
                                       Use spdm_pqc_sig_free() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from raw data buffer.
**/
boolean
spdm_pqc_sig_set_public_key (
  IN   pqc_algo_t     pqc_sig_algo,
  IN   const uint8  *raw_data,
  IN   uintn        raw_data_size,
  OUT  void         **context
  )
{
  uintn                nid;
  boolean              result;

  nid = spdm_get_pqc_sig_nid (pqc_sig_algo);
  if (nid == 0) {
    return FALSE;
  }
  *context = pqc_sig_new_by_nid (nid);
  if (*context == NULL) {
    return FALSE;
  }
  result = pqc_sig_set_public_key (*context, raw_data, raw_data_size);
  if (!result) {
    pqc_sig_free (*context);
    return FALSE;
  }
  return TRUE;
}

/**
  Release the specified PQC SIG context,
  based upon negotiated PQC SIG algorithm.

  @param  pqc_sig_algo                   SPDM pqc_sig_algo
  @param  context                      Pointer to the PQC SIG context.
**/
void
spdm_pqc_sig_free (
  IN   pqc_algo_t     pqc_sig_algo,
  IN   void         *context
  )
{
  pqc_sig_free (context);
}

/**
  Verifies the PQC signature,
  based upon negotiated PQC SIG algorithm.

  @param  pqc_sig_algo                   SPDM pqc_sig_algo
  @param  context                      Pointer to the PQC SIG context..
  @param  message                      Pointer to octet message to be checked (before hash).
  @param  message_size                  Size of the message in bytes.
  @param  signature                    Pointer to PQC SIG signature to be verified.
  @param  sig_size                      Size of signature in bytes.

  @retval  TRUE   Valid PQC SIG signature.
  @retval  FALSE  Invalid PQC SIG signature or invalid PQC SIG context.
**/
boolean
spdm_pqc_sig_verify (
  IN  pqc_algo_t     pqc_sig_algo,
  IN  void         *context,
  IN  const uint8  *message,
  IN  uintn        message_size,
  IN  const uint8  *signature,
  IN  uintn        sig_size
  )
{
  return pqc_sig_verify (context, message, message_size, signature, sig_size);
}

/**
  Retrieve the Private Key from the raw data.

  @param  pqc_sig_algo                   SPDM pqc_sig_algo
  @param  raw_data                      Pointer to raw data buffer to hold the private key.
  @param  raw_data_size                  Size of the raw data buffer in bytes.
  @param  context                      Pointer to new-generated PQC SIG context which contain the retrieved private key component.
                                       Use spdm_pqc_sig_free() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid raw data buffer.
**/
boolean
spdm_pqc_sig_set_private_key (
  IN   pqc_algo_t     pqc_sig_algo,
  IN   const uint8  *raw_data,
  IN   uintn        raw_data_size,
  OUT  void         **context
  )
{
  uintn                nid;
  boolean              result;

  nid = spdm_get_pqc_sig_nid (pqc_sig_algo);
  if (nid == 0) {
    return FALSE;
  }
  *context = pqc_sig_new_by_nid (nid);
  if (*context == NULL) {
    return FALSE;
  }
  result = pqc_sig_set_private_key (*context, raw_data, raw_data_size);
  if (!result) {
    pqc_sig_free (*context);
    return FALSE;
  }
  return TRUE;
}

/**
  Carries out the signature generation.

  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  @param  pqc_sig_algo                   SPDM pqc_sig_algo
  @param  context                      Pointer to the PQC SIG context.
  @param  message                      Pointer to octet message to be signed (before hash).
  @param  message_size                  Size of the message in bytes.
  @param  signature                    Pointer to buffer to receive signature.
  @param  sig_size                      On input, the size of signature buffer in bytes.
                                       On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.
**/
boolean
spdm_pqc_sig_sign (
  IN      pqc_algo_t     pqc_sig_algo,
  IN      void         *context,
  IN      const uint8  *message,
  IN      uintn        message_size,
  OUT     uint8        *signature,
  IN OUT  uintn        *sig_size
  )
{
  return pqc_sig_sign (context, message, message_size, signature, sig_size);
}

/**
  This function returns the SPDM requester PQC SIG algorithm size.

  @param  pqc_req_sig_algo                SPDM pqc_req_sig_algo

  @return SPDM requester PQC SIG algorithm size.
**/
uint32
spdm_get_pqc_req_sig_public_key_size (
  IN   pqc_algo_t     pqc_req_sig_algo
  )
{
  return spdm_get_pqc_sig_public_key_size (pqc_req_sig_algo);
}

/**
  This function returns the SPDM requester PQC SIG algorithm size.

  @param  pqc_req_sig_algo                SPDM pqc_req_sig_algo

  @return SPDM requester PQC SIG algorithm size.
**/
uint32
spdm_get_pqc_req_sig_signature_size (
  IN   pqc_algo_t     pqc_req_sig_algo
  )
{
  return spdm_get_pqc_sig_signature_size (pqc_req_sig_algo);
}

/**
  Retrieve the PQC SIG Public Key from raw data,
  based upon negotiated requester PQC SIG algorithm.

  @param  pqc_req_sig_algo                SPDM pqc_req_sig_algo
  @param  raw_data                      Pointer to raw data buffer to hold the public key.
  @param  raw_data_size                  Size of the raw data buffer in bytes.
  @param  context                      Pointer to new-generated PQC SIG context which contain the retrieved public key component.
                                       Use spdm_pqc_sig_free() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from raw data buffer.
**/
boolean
spdm_pqc_req_sig_set_public_key (
  IN   pqc_algo_t     pqc_req_sig_algo,
  IN   const uint8  *raw_data,
  IN   uintn        raw_data_size,
  OUT  void         **context
  )
{
  return spdm_pqc_sig_set_public_key (pqc_req_sig_algo, raw_data, raw_data_size, context);
}

/**
  Release the specified PQC SIG context,
  based upon negotiated requester PQC SIG algorithm.

  @param  pqc_req_sig_algo                SPDM pqc_req_sig_algo
  @param  context                      Pointer to the PQC SIG context.
**/
void
spdm_pqc_req_sig_free (
  IN   pqc_algo_t     pqc_req_sig_algo,
  IN   void         *context
  )
{
  spdm_pqc_sig_free (pqc_req_sig_algo, context);
}

/**
  Verifies the PQC SIG signature,
  based upon negotiated requester PQC SIG algorithm.

  @param  pqc_req_sig_algo                SPDM pqc_req_sig_algo
  @param  context                      Pointer to the PQC SIG context..
  @param  message                      Pointer to octet message to be checked (before hash).
  @param  message_size                  Size of the message in bytes.
  @param  signature                    Pointer to PQC SIG signature to be verified.
  @param  sig_size                      Size of signature in bytes.

  @retval  TRUE   Valid PQC SIG signature.
  @retval  FALSE  Invalid PQC SIG signature or invalid PQC SIG context.
**/
boolean
spdm_pqc_req_sig_verify (
  IN  pqc_algo_t     pqc_req_sig_algo,
  IN  void         *context,
  IN  const uint8  *message,
  IN  uintn        message_size,
  IN  const uint8  *signature,
  IN  uintn        sig_size
  )
{
  return spdm_pqc_sig_verify (pqc_req_sig_algo, context, message, message_size, signature, sig_size);
}

/**
  Retrieve the Private Key from the raw data.

  @param  pqc_req_sig_algo                SPDM pqc_req_sig_algo
  @param  raw_data                      Pointer to raw data buffer to hold the private key.
  @param  raw_data_size                  Size of the raw data buffer in bytes.
  @param  context                      Pointer to new-generated PQC SIG context which contain the retrieved private key component.
                                       Use spdm_pqc_sig_free() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid raw data buffer.
**/
boolean
spdm_pqc_req_sig_set_private_key (
  IN   pqc_algo_t     pqc_req_sig_algo,
  IN   const uint8  *raw_data,
  IN   uintn        raw_data_size,
  OUT  void         **context
  )
{
  return spdm_pqc_sig_set_private_key (pqc_req_sig_algo, raw_data, raw_data_size, context);
}

/**
  Carries out the signature generation.

  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  @param  pqc_req_sig_algo                SPDM pqc_req_sig_algo
  @param  context                      Pointer to the PQC SIG context.
  @param  message                      Pointer to octet message to be signed (before hash).
  @param  message_size                  Size of the message in bytes.
  @param  signature                    Pointer to buffer to receive signature.
  @param  sig_size                      On input, the size of signature buffer in bytes.
                                       On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.
**/
boolean
spdm_pqc_req_sig_sign (
  IN      pqc_algo_t     pqc_req_sig_algo,
  IN      void         *context,
  IN      const uint8  *message,
  IN      uintn        message_size,
  OUT     uint8        *signature,
  IN OUT  uintn        *sig_size
  )
{
  return spdm_pqc_sig_sign (pqc_req_sig_algo, context, message, message_size, signature, sig_size);
}

/**
  This function returns the SPDM PQC KEM algorithm key size.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo

  @return SPDM PQC KEM algorithm key size.
**/
uint32
spdm_get_pqc_kem_public_key_size (
  IN      pqc_algo_t     pqc_kem_algo
  )
{
  spdm_pqc_algo_table_t  *algo_entry;

  algo_entry = spdm_get_pqc_kem_algo_entry (pqc_kem_algo);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)pqc_get_oqs_kem_public_key_size (algo_entry->nid);
}

/**
  This function returns the SPDM PQC KEM algorithm key size.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo

  @return SPDM PQC KEM algorithm key size.
**/
uint32
spdm_get_pqc_kem_shared_key_size (
  IN      pqc_algo_t     pqc_kem_algo
  )
{
  spdm_pqc_algo_table_t  *algo_entry;

  algo_entry = spdm_get_pqc_kem_algo_entry (pqc_kem_algo);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)pqc_get_oqs_kem_shared_key_size (algo_entry->nid);
}

/**
  This function returns the SPDM PQC KEM algorithm key size.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo

  @return SPDM PQC KEM algorithm key size.
**/
uint32
spdm_get_pqc_kem_cipher_text_size (
  IN      pqc_algo_t     pqc_kem_algo
  )
{
  spdm_pqc_algo_table_t  *algo_entry;

  algo_entry = spdm_get_pqc_kem_algo_entry (pqc_kem_algo);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)pqc_get_oqs_kem_cipher_text_size (algo_entry->nid);
}

/**
  Allocates and Initializes one PQC KEM context for subsequent use,
  based upon negotiated PQC KEM algorithm.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo

  @return  Pointer to the PQC KEM context that has been initialized.
**/
void *
spdm_pqc_kem_new (
  IN      pqc_algo_t     pqc_kem_algo
  )
{
  uintn                nid;

  nid = spdm_get_pqc_kem_nid (pqc_kem_algo);
  if (nid == 0) {
    return NULL;
  }
  return pqc_kem_new_by_nid (nid);
}

/**
  Release the specified PQC KEM context,
  based upon negotiated PQC KEM algorithm.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo
  @param  context                      Pointer to the PQC KEM context.
**/
void
spdm_pqc_kem_free (
  IN      pqc_algo_t     pqc_kem_algo,
  IN      void         *context
  )
{
  pqc_kem_free (context);
}

/**
  Generate key pairs.

  @param  context                      Pointer to the PQC KEM context.

  @retval  TRUE   Key pairs are generated.
  @retval  FALSE  Fail to generate the key pairs.
**/
boolean
spdm_pqc_kem_generate_key (
  IN      pqc_algo_t     pqc_kem_algo,
  IN      void         *context
  )
{
  return pqc_kem_generate_key (context);
}

/**
  Retrieve the PQC Public Key.

  @param  context                      Pointer to the PQC SIG context.
  @param  public_key                    Pointer to the buffer to receive generated public key.
  @param  public_key_size                On input, the size of public_key buffer in bytes.
                                       On output, the size of data returned in public_key buffer in bytes.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from raw data buffer.
**/
boolean
spdm_pqc_kem_get_public_key (
  IN      pqc_algo_t     pqc_kem_algo,
  IN      void         *context,
  OUT     uint8        *public_key,
  IN OUT  uintn        *public_key_size
  )
{
  return pqc_kem_get_public_key (context, public_key, public_key_size);
}

/**
  Generate shared key and return the encap data for the shared key with peer public key,
  based upon negotiated PQC KEM algorithm.

  @param  context                      Pointer to the PQC KEM context.
  @param  peer_public_key                Pointer to the peer's public key.
  @param  peer_public_key_size            Size of peer's public key in bytes.
  @param  shared_key                    Pointer to the buffer to receive shared key.
  @param  shared_key_size                On input, the size of shared Key buffer in bytes.
                                       On output, the size of data returned in shared Key buffer in bytes.
  @param  cipher_text                   Pointer to the buffer to receive encapsulated cipher text for the shared key.
  @param  cipher_text_size               On input, the size of cipher text buffer in bytes.
                                       On output, the size of data returned in cipher text buffer in bytes.

  @retval TRUE   PQC KEM shared key is generated and encapsulated succeeded.
  @retval FALSE  PQC KEM shared key generation failed.
  @retval FALSE  SharedKeySize or CipherTextSize is not large enough.
**/
boolean
spdm_pqc_kem_encap (
  IN      pqc_algo_t     pqc_kem_algo,
  IN OUT  void         *context,
  IN      const uint8  *peer_public_key,
  IN      uintn        peer_public_key_size,
  OUT     uint8        *shared_key,
  IN OUT  uintn        *shared_key_size,
  OUT     uint8        *cipher_text,
  IN OUT  uintn        *cipher_text_size
  )
{
  return pqc_kem_encap (context, peer_public_key, peer_public_key_size, shared_key, shared_key_size, cipher_text, cipher_text_size);
}

/**
  Decap the cipher text to shared key with private key,
  based upon negotiated PQC KEM algorithm.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo
  @param  context                      Pointer to the PQC KEM context.
  @param  shared_key                    Pointer to the buffer to receive shared key.
  @param  shared_key_size                On input, the size of shared Key buffer in bytes.
                                       On output, the size of data returned in shared Key buffer in bytes.
  @param  cipher_text                   Pointer to the buffer to encapsulated cipher text for the shared key.
  @param  cipher_text_size               The size of cipher text buffer in bytes.

  @retval TRUE   PQC KEM shared key is decapsulated succeeded.
  @retval FALSE  PQC KEM shared key decapsulation failed.
  @retval FALSE  SharedKeySize is not large enough.
**/
boolean
spdm_pqc_kem_decap (
  IN      pqc_algo_t     pqc_kem_algo,
  IN OUT  void         *context,
  OUT     uint8        *shared_key,
  IN OUT  uintn        *shared_key_size,
  IN      uint8        *cipher_text,
  IN      uintn        cipher_text_size
  )
{
  return pqc_kem_decap (context, shared_key, shared_key_size, cipher_text, cipher_text_size);
}

//
// Hybrid
//

/**
  Retrieve the asymmetric public key from one DER-encoded X509 certificate,
  based upon negotiated asymmetric algorithm.

  @param  cert                         Pointer to the DER-encoded X509 certificate.
  @param  cert_size                     size of the X509 certificate in bytes.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   public key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
boolean
spdm_hybrid_get_public_key_from_x509 (
  IN   const uint8                  *cert,
  IN   uintn                        cert_size,
  OUT  void                         **context
  )
{
  return pqc_hybrid_get_public_key_from_x509 (cert, cert_size, context);
}

/**
  Retrieve the Private key from the password-protected PEM key data.

  @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
  @param  pem_size                      size of the PEM key data in bytes.
  @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use spdm_asym_free() function to free the resource.

  @retval  TRUE   Private key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
boolean
spdm_hybrid_get_private_key_from_pem (
  IN   const uint8                  *pem_data,
  IN   uintn                        pem_size,
  IN   const char8                  *password,
  OUT  void                         **context
  )
{
  return pqc_hybrid_get_private_key_from_pem (pem_data, pem_size, password, context);
}

/**
  Carries out the signature generation.

  If the signature buffer is too small to hold the contents of signature, FALSE
  is returned and sig_size is set to the required buffer size to obtain the signature.

  @param  context                      Pointer to the PQC SIG context.
  @param  message                      Pointer to octet message to be signed (before hash).
  @param  message_size                  Size of the message in bytes.
  @param  signature                    Pointer to buffer to receive signature.
  @param  sig_size                      On input, the size of signature buffer in bytes.
                                       On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.
**/
boolean
spdm_hybrid_sig_sign (
  IN      void         *context,
  IN      const uint8  *message,
  IN      uintn        message_size,
  OUT     uint8        *signature,
  IN OUT  uintn        *sig_size
  )
{
  return pqc_hybrid_sign (context, 0, message, message_size, signature, sig_size);
}

/**
  Verifies the PQC signature,
  based upon negotiated PQC SIG algorithm.

  @param  context                      Pointer to the PQC SIG context..
  @param  message                      Pointer to octet message to be checked (before hash).
  @param  message_size                  Size of the message in bytes.
  @param  signature                    Pointer to PQC SIG signature to be verified.
  @param  sig_size                      Size of signature in bytes.

  @retval  TRUE   Valid PQC SIG signature.
  @retval  FALSE  Invalid PQC SIG signature or invalid PQC SIG context.
**/
boolean
spdm_hybrid_sig_verify (
  IN  void         *context,
  IN  const uint8  *message,
  IN  uintn        message_size,
  IN  const uint8  *signature,
  IN  uintn        sig_size
  )
{
  return pqc_hybrid_verify (context, 0, message, message_size, signature, sig_size);
}

/**
  Release the specified PQC SIG context,
  based upon negotiated PQC SIG algorithm.

  @param  context                      Pointer to the PQC SIG context.
**/
void
spdm_hybrid_sig_free (
  IN   void         *context
  )
{
  pqc_hybrid_free (context);
}
