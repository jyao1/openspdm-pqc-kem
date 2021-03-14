/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmPqcCryptLib.h>
#include <Library/PqcCryptLib.h>

typedef struct {
  UINTN Nid;
  UINT8 ByteIndex;
  UINT8 Byte;
} SPDM_PQC_ALGO_TABLE;

SPDM_PQC_ALGO_TABLE mSpdmPqcSigAlgoNameTable[] = {
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


SPDM_PQC_ALGO_TABLE mSpdmPqcKemAlgoNameTable[] = {
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

BOOLEAN
SpdmGetSingleBit (
  IN   PQC_ALGO     PqcSigAlgo,
  OUT  UINT8        *ByteIndex,
  OUT  UINT8        *BitIndex
  )
{
  UINT8  Index;
  UINT8  Byte;
  UINT8  Bit;
  
  Byte = 0;
  for (Index = 0; Index < sizeof(PqcSigAlgo); Index++) {
    if (PqcSigAlgo[Index] != 0) {
      if (Byte == 0) {
        Byte = PqcSigAlgo[Index];
        *ByteIndex = Index;
      } else {
        // dup byte set
        ASSERT(FALSE);
        return FALSE;
      }
    }
  }
  if (Byte == 0) {
    // no byte set
    ASSERT(FALSE);
    return FALSE;
  }

  Bit = 0xFF;
  for (Index = 0; Index < 8; Index++) {
    if ((Byte & (1 << Index)) != 0) {
      if (Bit == 0xFF) {
        Bit = Index;
        *BitIndex = Index;
      } else {
        // dup bit set
        ASSERT(FALSE);
        return FALSE;
      }
    }
  }
  if (Bit == 0xFF) {
    // no bit set
    ASSERT(FALSE);
    return FALSE;
  }

  return TRUE;
}

SPDM_PQC_ALGO_TABLE *
SpdmGetPqcAlgoEntry (
  IN   PQC_ALGO             PqcSigAlgo,
  IN   SPDM_PQC_ALGO_TABLE  *Table,
  IN   UINTN                TableCount
  )
{
  UINT8   ByteIndex;
  UINT8   BitIndex;
  BOOLEAN Result;
  UINT8   Index;

  Result = SpdmGetSingleBit (PqcSigAlgo, &ByteIndex, &BitIndex);
  if (!Result) {
    return NULL;
  }

  for (Index = 0; Index < TableCount; Index++) {
    if ((Table[Index].ByteIndex == ByteIndex) && (Table[Index].Byte == (1 << BitIndex))) {
      return &Table[Index];
    }
  }
  return NULL;
}

SPDM_PQC_ALGO_TABLE *
SpdmGetPqcSigAlgoEntry (
  IN   PQC_ALGO     PqcSigAlgo
  )
{
  return SpdmGetPqcAlgoEntry (PqcSigAlgo, mSpdmPqcSigAlgoNameTable, ARRAY_SIZE(mSpdmPqcSigAlgoNameTable));
}

SPDM_PQC_ALGO_TABLE *
SpdmGetPqcKemAlgoEntry (
  IN   PQC_ALGO     PqcKemAlgo
  )
{
  return SpdmGetPqcAlgoEntry (PqcKemAlgo, mSpdmPqcKemAlgoNameTable, ARRAY_SIZE(mSpdmPqcKemAlgoNameTable));
}

UINTN
SpdmGetPqcSigNid (
  IN   PQC_ALGO     PqcSigAlgo
  )
{
  SPDM_PQC_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = SpdmGetPqcSigAlgoEntry (PqcSigAlgo);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return AlgoEntry->Nid;
}

UINTN
SpdmGetPqcKemNid (
  IN   PQC_ALGO     PqcKemAlgo
  )
{
  SPDM_PQC_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = SpdmGetPqcKemAlgoEntry (PqcKemAlgo);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return AlgoEntry->Nid;
}

/**
  This function returns the SPDM PqcSigAlgo algorithm size.

  @param  PqcSigAlgo                   SPDM PqcSigAlgo

  @return SPDM PqcSigAlgo algorithm size.
**/
UINT32
EFIAPI
GetSpdmPqcSigSignatureSize (
  IN   PQC_ALGO     PqcSigAlgo
  )
{
  SPDM_PQC_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = SpdmGetPqcSigAlgoEntry (PqcSigAlgo);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return (UINT32)PqcGetOqsSigSignatureSize (AlgoEntry->Nid);
}

/**
  Retrieve the PQC Public Key from raw data,
  based upon negotiated PQC SIG algorithm.

  @param  PqcSigAlgo                   SPDM PqcSigAlgo
  @param  RawData                      Pointer to raw data buffer to hold the public key.
  @param  RawDataSize                  Size of the raw data buffer in bytes.
  @param  Context                      Pointer to new-generated PQC SIG context which contain the retrieved public key component.
                                       Use SpdmPqcSigFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from raw data buffer.
**/
BOOLEAN
EFIAPI
SpdmPqcSigSetPublicKey (
  IN   PQC_ALGO     PqcSigAlgo,
  IN   CONST UINT8  *RawData,
  IN   UINTN        RawDataSize,
  OUT  VOID         **Context
  )
{
  UINTN                Nid;
  BOOLEAN              Result;

  Nid = SpdmGetPqcSigNid (PqcSigAlgo);
  if (Nid == 0) {
    return FALSE;
  }
  *Context = PqcSigNewByNid (Nid);
  if (*Context == NULL) {
    return FALSE;
  }
  Result = PqcSigSetPublicKey (*Context, RawData, RawDataSize);
  if (!Result) {
    PqcSigFree (*Context);
    return FALSE;
  }
  return TRUE;
}

/**
  Release the specified PQC SIG context,
  based upon negotiated PQC SIG algorithm.

  @param  PqcSigAlgo                   SPDM PqcSigAlgo
  @param  Context                      Pointer to the PQC SIG context.
**/
VOID
EFIAPI
SpdmPqcSigFree (
  IN   PQC_ALGO     PqcSigAlgo,
  IN   VOID         *Context
  )
{
  PqcSigFree (Context);
}

/**
  Verifies the PQC signature,
  based upon negotiated PQC SIG algorithm.

  @param  PqcSigAlgo                   SPDM PqcSigAlgo
  @param  Context                      Pointer to the PQC SIG context..
  @param  Message                      Pointer to octet message to be checked (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to PQC SIG signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid PQC SIG signature.
  @retval  FALSE  Invalid PQC SIG signature or invalid PQC SIG context.
**/
BOOLEAN
EFIAPI
SpdmPqcSigVerify (
  IN  PQC_ALGO     PqcSigAlgo,
  IN  VOID         *Context,
  IN  CONST UINT8  *Message,
  IN  UINTN        MessageSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  )
{
  return PqcSigVerify (Context, Message, MessageSize, Signature, SigSize);
}

/**
  Retrieve the Private Key from the raw data.

  @param  PqcSigAlgo                   SPDM PqcSigAlgo
  @param  RawData                      Pointer to raw data buffer to hold the private key.
  @param  RawDataSize                  Size of the raw data buffer in bytes.
  @param  Context                      Pointer to new-generated PQC SIG context which contain the retrieved private key component.
                                       Use SpdmPqcSigFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid raw data buffer.
**/
BOOLEAN
EFIAPI
SpdmPqcSigSetPrivateKey (
  IN   PQC_ALGO     PqcSigAlgo,
  IN   CONST UINT8  *RawData,
  IN   UINTN        RawDataSize,
  OUT  VOID         **Context
  )
{
  UINTN                Nid;
  BOOLEAN              Result;

  Nid = SpdmGetPqcSigNid (PqcSigAlgo);
  if (Nid == 0) {
    return FALSE;
  }
  *Context = PqcSigNewByNid (Nid);
  if (*Context == NULL) {
    return FALSE;
  }
  Result = PqcSigSetPrivateKey (*Context, RawData, RawDataSize);
  if (!Result) {
    PqcSigFree (*Context);
    return FALSE;
  }
  return TRUE;
}

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  @param  PqcSigAlgo                   SPDM PqcSigAlgo
  @param  Context                      Pointer to the PQC SIG context.
  @param  Message                      Pointer to octet message to be signed (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to buffer to receive signature.
  @param  SigSize                      On input, the size of Signature buffer in bytes.
                                       On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
BOOLEAN
EFIAPI
SpdmPqcSigSign (
  IN      PQC_ALGO     PqcSigAlgo,
  IN      VOID         *Context,
  IN      CONST UINT8  *Message,
  IN      UINTN        MessageSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  return PqcSigSign (Context, Message, MessageSize, Signature, SigSize);
}

/**
  This function returns the SPDM requester PQC SIG algorithm size.

  @param  ReqPqcSigAlgo                SPDM ReqPqcSigAlgo

  @return SPDM requester PQC SIG algorithm size.
**/
UINT32
EFIAPI
GetSpdmReqPqcSigSignatureSize (
  IN   PQC_ALGO     ReqPqcSigAlgo
  )
{
  return GetSpdmPqcSigSignatureSize (ReqPqcSigAlgo);
}

/**
  Retrieve the PQC SIG Public Key from raw data,
  based upon negotiated requester PQC SIG algorithm.

  @param  ReqPqcSigAlgo                SPDM ReqPqcSigAlgo
  @param  RawData                      Pointer to raw data buffer to hold the public key.
  @param  RawDataSize                  Size of the raw data buffer in bytes.
  @param  Context                      Pointer to new-generated PQC SIG context which contain the retrieved public key component.
                                       Use SpdmPqcSigFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from raw data buffer.
**/
BOOLEAN
EFIAPI
SpdmReqPqcSigSetPublicKey (
  IN   PQC_ALGO     ReqPqcSigAlgo,
  IN   CONST UINT8  *RawData,
  IN   UINTN        RawDataSize,
  OUT  VOID         **Context
  )
{
  return SpdmPqcSigSetPublicKey (ReqPqcSigAlgo, RawData, RawDataSize, Context);
}

/**
  Release the specified PQC SIG context,
  based upon negotiated requester PQC SIG algorithm.

  @param  ReqPqcSigAlgo                SPDM ReqPqcSigAlgo
  @param  Context                      Pointer to the PQC SIG context.
**/
VOID
EFIAPI
SpdmReqPqcSigFree (
  IN   PQC_ALGO     ReqPqcSigAlgo,
  IN   VOID         *Context
  )
{
  SpdmPqcSigFree (ReqPqcSigAlgo, Context);
}

/**
  Verifies the PQC SIG signature,
  based upon negotiated requester PQC SIG algorithm.

  @param  ReqPqcSigAlgo                SPDM ReqPqcSigAlgo
  @param  Context                      Pointer to the PQC SIG context..
  @param  Message                      Pointer to octet message to be checked (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to PQC SIG signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid PQC SIG signature.
  @retval  FALSE  Invalid PQC SIG signature or invalid PQC SIG context.
**/
BOOLEAN
EFIAPI
SpdmReqPqcSigVerify (
  IN  PQC_ALGO     ReqPqcSigAlgo,
  IN  VOID         *Context,
  IN  CONST UINT8  *Message,
  IN  UINTN        MessageSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  )
{
  return SpdmPqcSigVerify (ReqPqcSigAlgo, Context, Message, MessageSize, Signature, SigSize);
}

/**
  Retrieve the Private Key from the raw data.

  @param  ReqPqcSigAlgo                SPDM ReqPqcSigAlgo
  @param  RawData                      Pointer to raw data buffer to hold the private key.
  @param  RawDataSize                  Size of the raw data buffer in bytes.
  @param  Context                      Pointer to new-generated PQC SIG context which contain the retrieved private key component.
                                       Use SpdmPqcSigFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid raw data buffer.
**/
BOOLEAN
EFIAPI
SpdmReqPqcSigSetPrivateKey (
  IN   PQC_ALGO     ReqPqcSigAlgo,
  IN   CONST UINT8  *RawData,
  IN   UINTN        RawDataSize,
  OUT  VOID         **Context
  )
{
  return SpdmPqcSigSetPrivateKey (ReqPqcSigAlgo, RawData, RawDataSize, Context);
}

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  @param  ReqPqcSigAlgo                SPDM ReqPqcSigAlgo
  @param  Context                      Pointer to the PQC SIG context.
  @param  Message                      Pointer to octet message to be signed (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to buffer to receive signature.
  @param  SigSize                      On input, the size of Signature buffer in bytes.
                                       On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
BOOLEAN
EFIAPI
SpdmReqPqcSigSign (
  IN      PQC_ALGO     ReqPqcSigAlgo,
  IN      VOID         *Context,
  IN      CONST UINT8  *Message,
  IN      UINTN        MessageSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  return SpdmPqcSigSign (ReqPqcSigAlgo, Context, Message, MessageSize, Signature, SigSize);
}

/**
  This function returns the SPDM PQC KEM algorithm key size.

  @param  PqcKemAlgo                   SPDM PqcKemAlgo

  @return SPDM PQC KEM algorithm key size.
**/
UINT32
EFIAPI
GetSpdmPqcKemPubKeySize (
  IN      PQC_ALGO     PqcKemAlgo
  )
{
  SPDM_PQC_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = SpdmGetPqcKemAlgoEntry (PqcKemAlgo);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return (UINT32)PqcGetOqsKemPubKeySize (AlgoEntry->Nid);
}

/**
  Allocates and Initializes one PQC KEM Context for subsequent use,
  based upon negotiated PQC KEM algorithm.

  @param  PqcKemAlgo                   SPDM PqcKemAlgo

  @return  Pointer to the PQC KEM Context that has been initialized.
**/
VOID *
EFIAPI
SpdmPqcKemNew (
  IN      PQC_ALGO     PqcKemAlgo
  )
{
  UINTN                Nid;

  Nid = SpdmGetPqcSigNid (PqcKemAlgo);
  if (Nid == 0) {
    return NULL;
  }
  return PqcKemNewByNid (Nid);
}

/**
  Release the specified PQC KEM context,
  based upon negotiated PQC KEM algorithm.

  @param  PqcKemAlgo                   SPDM PqcKemAlgo
  @param  Context                      Pointer to the PQC KEM context.
**/
VOID
EFIAPI
SpdmPqcKemFree (
  IN      PQC_ALGO     PqcKemAlgo,
  IN      VOID         *Context
  )
{
  PqcKemFree (Context);
}

/**
  Generate shared key and return the encap data for the shared key with peer public key,
  based upon negotiated PQC KEM algorithm.

  @param  Context                      Pointer to the PQC KEM context.
  @param  PeerPublicKey                Pointer to the peer's public key.
  @param  PeerPublicKeySize            Size of peer's public key in bytes.
  @param  SharedKey                    Pointer to the buffer to receive shared key.
  @param  SharedKeySize                On input, the size of shared Key buffer in bytes.
                                       On output, the size of data returned in shared Key buffer in bytes.
  @param  CipherText                   Pointer to the buffer to receive encapsulated cipher text for the shared key.
  @param  CipherTextSize               On input, the size of cipher text buffer in bytes.
                                       On output, the size of data returned in cipher text buffer in bytes.

  @retval TRUE   PQC KEM shared key is generated and encapsulated succeeded.
  @retval FALSE  PQC KEM shared key generation failed.
  @retval FALSE  SharedKeySize or CipherTextSize is not large enough.
**/
BOOLEAN
EFIAPI
SpdmPqcKemEncap (
  IN      PQC_ALGO     PqcKemAlgo,
  IN OUT  VOID         *Context,
  IN      CONST UINT8  *PeerPublic,
  IN      UINTN        PeerPublicSize,
  OUT     UINT8        *SharedKey,
  IN OUT  UINTN        *SharedKeySize,
  OUT     UINT8        *CipherText,
  IN OUT  UINTN        *CipherTextSize
  )
{
  return PqcKemEncap (Context, PeerPublic, PeerPublicSize, SharedKey, SharedKeySize, CipherText, CipherTextSize);
}

/**
  Decap the cipher text to shared key with private key,
  based upon negotiated PQC KEM algorithm.

  @param  PqcKemAlgo                   SPDM PqcKemAlgo
  @param  Context                      Pointer to the PQC KEM context.
  @param  SharedKey                    Pointer to the buffer to receive shared key.
  @param  SharedKeySize                On input, the size of shared Key buffer in bytes.
                                       On output, the size of data returned in shared Key buffer in bytes.
  @param  CipherText                   Pointer to the buffer to encapsulated cipher text for the shared key.
  @param  CipherTextSize               The size of cipher text buffer in bytes.

  @retval TRUE   PQC KEM shared key is decapsulated succeeded.
  @retval FALSE  PQC KEM shared key decapsulation failed.
  @retval FALSE  SharedKeySize is not large enough.
**/
BOOLEAN
EFIAPI
SpdmPqcKemDecap (
  IN      PQC_ALGO     PqcKemAlgo,
  IN OUT  VOID         *Context,
  OUT     UINT8        *SharedKey,
  IN OUT  UINTN        *SharedKeySize,
  IN      UINT8        *CipherText,
  IN      UINTN        CipherTextSize
  )
{
  return PqcKemDecap (Context, SharedKey, SharedKeySize, CipherText, CipherTextSize);
}

