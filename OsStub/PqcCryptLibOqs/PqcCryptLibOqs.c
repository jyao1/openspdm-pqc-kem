/** @file
  common library.
  It follows the Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/PqcCryptLib.h>
#include <oqs/sig.h>
#include <oqs/sig_dilithium.h>
#include <oqs/sig_falcon.h>
#include <oqs/sig_picnic.h>
#include <oqs/sig_rainbow.h>
#include <oqs/sig_sphincs.h>
#include <oqs/kem.h>
#include <oqs/kem_classic_mceliece.h>
#include <oqs/kem_frodokem.h>
#include <oqs/kem_hqc.h>
#include <oqs/kem_kyber.h>
#include <oqs/kem_ntru.h>
#include <oqs/kem_ntruprime.h>
#include <oqs/kem_saber.h>
#include <oqs/kem_sike.h>

typedef struct {
  CHAR8 *Name;
  UINTN Nid;
  // SIG and KEM
  UINTN length_public_key;
  UINTN length_secret_key;
  // SIG
  UINTN length_signature;
  // KEM
  UINTN length_ciphertext;
  UINTN length_shared_secret;
} PQC_OQS_ALGO_TABLE;

PQC_OQS_ALGO_TABLE mPqcOqsSigAlgoNameTable[] = {
  {OQS_SIG_alg_picnic_L1_FS,                 PQC_CRYPTO_SIG_NID_PICNIC_L1_FS,                       OQS_SIG_picnic_L1_FS_length_public_key,                 OQS_SIG_picnic_L1_FS_length_secret_key,                 OQS_SIG_picnic_L1_FS_length_signature, 0},
  {OQS_SIG_alg_picnic_L1_UR,                 PQC_CRYPTO_SIG_NID_PICNIC_L1_UR,                       OQS_SIG_picnic_L1_UR_length_public_key,                 OQS_SIG_picnic_L1_UR_length_secret_key,                 OQS_SIG_picnic_L1_UR_length_signature, 0},
  {OQS_SIG_alg_picnic_L1_full,               PQC_CRYPTO_SIG_NID_PICNIC_L1_FULL,                     OQS_SIG_picnic_L1_full_length_public_key,               OQS_SIG_picnic_L1_full_length_secret_key,               OQS_SIG_picnic_L1_full_length_signature, 0},
  {OQS_SIG_alg_picnic_L3_FS,                 PQC_CRYPTO_SIG_NID_PICNIC_L3_FS,                       OQS_SIG_picnic_L3_FS_length_public_key,                 OQS_SIG_picnic_L3_FS_length_secret_key,                 OQS_SIG_picnic_L3_FS_length_signature, 0},
  {OQS_SIG_alg_picnic_L3_UR,                 PQC_CRYPTO_SIG_NID_PICNIC_L3_UR,                       OQS_SIG_picnic_L3_UR_length_public_key,                 OQS_SIG_picnic_L3_UR_length_secret_key,                 OQS_SIG_picnic_L3_UR_length_signature, 0},
  {OQS_SIG_alg_picnic_L3_full,               PQC_CRYPTO_SIG_NID_PICNIC_L3_FULL,                     OQS_SIG_picnic_L3_full_length_public_key,               OQS_SIG_picnic_L3_full_length_secret_key,               OQS_SIG_picnic_L3_full_length_signature, 0},
  {OQS_SIG_alg_picnic_L5_FS,                 PQC_CRYPTO_SIG_NID_PICNIC_L5_FS,                       OQS_SIG_picnic_L5_FS_length_public_key,                 OQS_SIG_picnic_L5_FS_length_secret_key,                 OQS_SIG_picnic_L5_FS_length_signature, 0},
  {OQS_SIG_alg_picnic_L5_UR,                 PQC_CRYPTO_SIG_NID_PICNIC_L5_UR,                       OQS_SIG_picnic_L5_UR_length_public_key,                 OQS_SIG_picnic_L5_UR_length_secret_key,                 OQS_SIG_picnic_L5_UR_length_signature, 0},
  {OQS_SIG_alg_picnic_L5_full,               PQC_CRYPTO_SIG_NID_PICNIC_L5_FULL,                     OQS_SIG_picnic_L5_full_length_public_key,               OQS_SIG_picnic_L5_full_length_secret_key,               OQS_SIG_picnic_L5_full_length_signature, 0},
  {OQS_SIG_alg_picnic3_L1,                   PQC_CRYPTO_SIG_NID_PICNIC3_L1,                         OQS_SIG_picnic3_L1_length_public_key,                   OQS_SIG_picnic3_L1_length_secret_key,                   OQS_SIG_picnic3_L1_length_signature, 0},
  {OQS_SIG_alg_picnic3_L3,                   PQC_CRYPTO_SIG_NID_PICNIC3_L3,                         OQS_SIG_picnic3_L3_length_public_key,                   OQS_SIG_picnic3_L3_length_secret_key,                   OQS_SIG_picnic3_L3_length_signature, 0},
  {OQS_SIG_alg_picnic3_L5,                   PQC_CRYPTO_SIG_NID_PICNIC3_L5,                         OQS_SIG_picnic3_L5_length_public_key,                   OQS_SIG_picnic3_L5_length_secret_key,                   OQS_SIG_picnic3_L5_length_signature, 0},
  {OQS_SIG_alg_dilithium_2,                  PQC_CRYPTO_SIG_NID_DILITHIUM_2,                        OQS_SIG_dilithium_2_length_public_key,                  OQS_SIG_dilithium_2_length_secret_key,                  OQS_SIG_dilithium_2_length_signature, 0},
  {OQS_SIG_alg_dilithium_3,                  PQC_CRYPTO_SIG_NID_DILITHIUM_3,                        OQS_SIG_dilithium_3_length_public_key,                  OQS_SIG_dilithium_3_length_secret_key,                  OQS_SIG_dilithium_3_length_signature, 0},
  {OQS_SIG_alg_dilithium_5,                  PQC_CRYPTO_SIG_NID_DILITHIUM_5,                        OQS_SIG_dilithium_5_length_public_key,                  OQS_SIG_dilithium_5_length_secret_key,                  OQS_SIG_dilithium_5_length_signature, 0},
  {OQS_SIG_alg_dilithium_2_aes,              PQC_CRYPTO_SIG_NID_DILITHIUM_2_AES,                    OQS_SIG_dilithium_2_aes_length_public_key,              OQS_SIG_dilithium_2_aes_length_secret_key,              OQS_SIG_dilithium_2_aes_length_signature, 0},
  {OQS_SIG_alg_dilithium_3_aes,              PQC_CRYPTO_SIG_NID_DILITHIUM_3_AES,                    OQS_SIG_dilithium_3_aes_length_public_key,              OQS_SIG_dilithium_3_aes_length_secret_key,              OQS_SIG_dilithium_3_aes_length_signature, 0},
  {OQS_SIG_alg_dilithium_5_aes,              PQC_CRYPTO_SIG_NID_DILITHIUM_5_AES,                    OQS_SIG_dilithium_5_aes_length_public_key,              OQS_SIG_dilithium_5_aes_length_secret_key,              OQS_SIG_dilithium_5_aes_length_signature, 0},
  {OQS_SIG_alg_falcon_512,                   PQC_CRYPTO_SIG_NID_FALCON_512,                         OQS_SIG_falcon_512_length_public_key,                   OQS_SIG_falcon_512_length_secret_key,                   OQS_SIG_falcon_512_length_signature, 0},
  {OQS_SIG_alg_falcon_1024,                  PQC_CRYPTO_SIG_NID_FALCON_1024,                        OQS_SIG_falcon_1024_length_public_key,                  OQS_SIG_falcon_1024_length_secret_key,                  OQS_SIG_falcon_1024_length_signature, 0},
  {OQS_SIG_alg_rainbow_I_classic,            PQC_CRYPTO_SIG_NID_RAINBOW_I_CLASSIC,                  OQS_SIG_rainbow_I_classic_length_public_key,            OQS_SIG_rainbow_I_classic_length_secret_key,            OQS_SIG_rainbow_I_classic_length_signature, 0},
  {OQS_SIG_alg_rainbow_I_circumzenithal,     PQC_CRYPTO_SIG_NID_RAINBOW_I_CIRCUMZENITHAL,           OQS_SIG_rainbow_I_circumzenithal_length_public_key,     OQS_SIG_rainbow_I_circumzenithal_length_secret_key,     OQS_SIG_rainbow_I_circumzenithal_length_signature, 0},
  {OQS_SIG_alg_rainbow_I_compressed,         PQC_CRYPTO_SIG_NID_RAINBOW_I_COMPRESSED,               OQS_SIG_rainbow_I_compressed_length_public_key,         OQS_SIG_rainbow_I_compressed_length_secret_key,         OQS_SIG_rainbow_I_compressed_length_signature, 0},
  {OQS_SIG_alg_rainbow_III_classic,          PQC_CRYPTO_SIG_NID_RAINBOW_III_CLASSIC,                OQS_SIG_rainbow_III_classic_length_public_key,          OQS_SIG_rainbow_III_classic_length_secret_key,          OQS_SIG_rainbow_III_classic_length_signature, 0},
  {OQS_SIG_alg_rainbow_III_circumzenithal,   PQC_CRYPTO_SIG_NID_RAINBOW_III_CIRCUMZENITHAL,         OQS_SIG_rainbow_III_circumzenithal_length_public_key,   OQS_SIG_rainbow_III_circumzenithal_length_secret_key,   OQS_SIG_rainbow_III_circumzenithal_length_signature, 0},
  {OQS_SIG_alg_rainbow_III_compressed,       PQC_CRYPTO_SIG_NID_RAINBOW_III_COMPRESSED,             OQS_SIG_rainbow_III_compressed_length_public_key,       OQS_SIG_rainbow_III_compressed_length_secret_key,       OQS_SIG_rainbow_III_compressed_length_signature, 0},
  {OQS_SIG_alg_rainbow_V_classic,            PQC_CRYPTO_SIG_NID_RAINBOW_V_CLASSIC,                  OQS_SIG_rainbow_V_classic_length_public_key,            OQS_SIG_rainbow_V_classic_length_secret_key,            OQS_SIG_rainbow_V_classic_length_signature, 0},
  {OQS_SIG_alg_rainbow_V_circumzenithal,     PQC_CRYPTO_SIG_NID_RAINBOW_V_CIRCUMZENITHAL,           OQS_SIG_rainbow_V_circumzenithal_length_public_key,     OQS_SIG_rainbow_V_circumzenithal_length_secret_key,     OQS_SIG_rainbow_V_circumzenithal_length_signature, 0},
  {OQS_SIG_alg_rainbow_V_compressed,         PQC_CRYPTO_SIG_NID_RAINBOW_V_COMPRESSED,               OQS_SIG_rainbow_V_compressed_length_public_key,         OQS_SIG_rainbow_V_compressed_length_secret_key,         OQS_SIG_rainbow_V_compressed_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_128f_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_ROBUST,         OQS_SIG_sphincs_haraka_128f_robust_length_public_key,   OQS_SIG_sphincs_haraka_128f_robust_length_secret_key,   OQS_SIG_sphincs_haraka_128f_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_128f_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_SIMPLE,         OQS_SIG_sphincs_haraka_128f_simple_length_public_key,   OQS_SIG_sphincs_haraka_128f_simple_length_secret_key,   OQS_SIG_sphincs_haraka_128f_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_128s_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_ROBUST,         OQS_SIG_sphincs_haraka_128s_robust_length_public_key,   OQS_SIG_sphincs_haraka_128s_robust_length_secret_key,   OQS_SIG_sphincs_haraka_128s_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_128s_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_SIMPLE,         OQS_SIG_sphincs_haraka_128s_simple_length_public_key,   OQS_SIG_sphincs_haraka_128s_simple_length_secret_key,   OQS_SIG_sphincs_haraka_128s_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_192f_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_ROBUST,         OQS_SIG_sphincs_haraka_192f_robust_length_public_key,   OQS_SIG_sphincs_haraka_192f_robust_length_secret_key,   OQS_SIG_sphincs_haraka_192f_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_192f_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_SIMPLE,         OQS_SIG_sphincs_haraka_192f_simple_length_public_key,   OQS_SIG_sphincs_haraka_192f_simple_length_secret_key,   OQS_SIG_sphincs_haraka_192f_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_192s_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_ROBUST,         OQS_SIG_sphincs_haraka_192s_robust_length_public_key,   OQS_SIG_sphincs_haraka_192s_robust_length_secret_key,   OQS_SIG_sphincs_haraka_192s_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_192s_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_SIMPLE,         OQS_SIG_sphincs_haraka_192s_simple_length_public_key,   OQS_SIG_sphincs_haraka_192s_simple_length_secret_key,   OQS_SIG_sphincs_haraka_192s_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_256f_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_ROBUST,         OQS_SIG_sphincs_haraka_256f_robust_length_public_key,   OQS_SIG_sphincs_haraka_256f_robust_length_secret_key,   OQS_SIG_sphincs_haraka_256f_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_256f_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_SIMPLE,         OQS_SIG_sphincs_haraka_256f_simple_length_public_key,   OQS_SIG_sphincs_haraka_256f_simple_length_secret_key,   OQS_SIG_sphincs_haraka_256f_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_256s_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_ROBUST,         OQS_SIG_sphincs_haraka_256s_robust_length_public_key,   OQS_SIG_sphincs_haraka_256s_robust_length_secret_key,   OQS_SIG_sphincs_haraka_256s_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_haraka_256s_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_SIMPLE,         OQS_SIG_sphincs_haraka_256s_simple_length_public_key,   OQS_SIG_sphincs_haraka_256s_simple_length_secret_key,   OQS_SIG_sphincs_haraka_256s_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_128f_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_ROBUST,         OQS_SIG_sphincs_sha256_128f_robust_length_public_key,   OQS_SIG_sphincs_sha256_128f_robust_length_secret_key,   OQS_SIG_sphincs_sha256_128f_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_128f_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_SIMPLE,         OQS_SIG_sphincs_sha256_128f_simple_length_public_key,   OQS_SIG_sphincs_sha256_128f_simple_length_secret_key,   OQS_SIG_sphincs_sha256_128f_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_128s_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_ROBUST,         OQS_SIG_sphincs_sha256_128s_robust_length_public_key,   OQS_SIG_sphincs_sha256_128s_robust_length_secret_key,   OQS_SIG_sphincs_sha256_128s_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_128s_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_SIMPLE,         OQS_SIG_sphincs_sha256_128s_simple_length_public_key,   OQS_SIG_sphincs_sha256_128s_simple_length_secret_key,   OQS_SIG_sphincs_sha256_128s_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_192f_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_ROBUST,         OQS_SIG_sphincs_sha256_192f_robust_length_public_key,   OQS_SIG_sphincs_sha256_192f_robust_length_secret_key,   OQS_SIG_sphincs_sha256_192f_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_192f_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_SIMPLE,         OQS_SIG_sphincs_sha256_192f_simple_length_public_key,   OQS_SIG_sphincs_sha256_192f_simple_length_secret_key,   OQS_SIG_sphincs_sha256_192f_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_192s_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_ROBUST,         OQS_SIG_sphincs_sha256_192s_robust_length_public_key,   OQS_SIG_sphincs_sha256_192s_robust_length_secret_key,   OQS_SIG_sphincs_sha256_192s_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_192s_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_SIMPLE,         OQS_SIG_sphincs_sha256_192s_simple_length_public_key,   OQS_SIG_sphincs_sha256_192s_simple_length_secret_key,   OQS_SIG_sphincs_sha256_192s_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_256f_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_ROBUST,         OQS_SIG_sphincs_sha256_256f_robust_length_public_key,   OQS_SIG_sphincs_sha256_256f_robust_length_secret_key,   OQS_SIG_sphincs_sha256_256f_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_256f_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_SIMPLE,         OQS_SIG_sphincs_sha256_256f_simple_length_public_key,   OQS_SIG_sphincs_sha256_256f_simple_length_secret_key,   OQS_SIG_sphincs_sha256_256f_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_256s_robust,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_ROBUST,         OQS_SIG_sphincs_sha256_256s_robust_length_public_key,   OQS_SIG_sphincs_sha256_256s_robust_length_secret_key,   OQS_SIG_sphincs_sha256_256s_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_sha256_256s_simple,   PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_SIMPLE,         OQS_SIG_sphincs_sha256_256s_simple_length_public_key,   OQS_SIG_sphincs_sha256_256s_simple_length_secret_key,   OQS_SIG_sphincs_sha256_256s_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_128f_robust, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_ROBUST,       OQS_SIG_sphincs_shake256_128f_robust_length_public_key, OQS_SIG_sphincs_shake256_128f_robust_length_secret_key, OQS_SIG_sphincs_shake256_128f_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_128f_simple, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_SIMPLE,       OQS_SIG_sphincs_shake256_128f_simple_length_public_key, OQS_SIG_sphincs_shake256_128f_simple_length_secret_key, OQS_SIG_sphincs_shake256_128f_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_128s_robust, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_ROBUST,       OQS_SIG_sphincs_shake256_128s_robust_length_public_key, OQS_SIG_sphincs_shake256_128s_robust_length_secret_key, OQS_SIG_sphincs_shake256_128s_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_128s_simple, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_SIMPLE,       OQS_SIG_sphincs_shake256_128s_simple_length_public_key, OQS_SIG_sphincs_shake256_128s_simple_length_secret_key, OQS_SIG_sphincs_shake256_128s_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_192f_robust, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_ROBUST,       OQS_SIG_sphincs_shake256_192f_robust_length_public_key, OQS_SIG_sphincs_shake256_192f_robust_length_secret_key, OQS_SIG_sphincs_shake256_192f_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_192f_simple, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_SIMPLE,       OQS_SIG_sphincs_shake256_192f_simple_length_public_key, OQS_SIG_sphincs_shake256_192f_simple_length_secret_key, OQS_SIG_sphincs_shake256_192f_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_192s_robust, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_ROBUST,       OQS_SIG_sphincs_shake256_192s_robust_length_public_key, OQS_SIG_sphincs_shake256_192s_robust_length_secret_key, OQS_SIG_sphincs_shake256_192s_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_192s_simple, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_SIMPLE,       OQS_SIG_sphincs_shake256_192s_simple_length_public_key, OQS_SIG_sphincs_shake256_192s_simple_length_secret_key, OQS_SIG_sphincs_shake256_192s_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_256f_robust, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_ROBUST,       OQS_SIG_sphincs_shake256_256f_robust_length_public_key, OQS_SIG_sphincs_shake256_256f_robust_length_secret_key, OQS_SIG_sphincs_shake256_256f_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_256f_simple, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_SIMPLE,       OQS_SIG_sphincs_shake256_256f_simple_length_public_key, OQS_SIG_sphincs_shake256_256f_simple_length_secret_key, OQS_SIG_sphincs_shake256_256f_simple_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_256s_robust, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_ROBUST,       OQS_SIG_sphincs_shake256_256s_robust_length_public_key, OQS_SIG_sphincs_shake256_256s_robust_length_secret_key, OQS_SIG_sphincs_shake256_256s_robust_length_signature, 0},
  {OQS_SIG_alg_sphincs_shake256_256s_simple, PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_SIMPLE,       OQS_SIG_sphincs_shake256_256s_simple_length_public_key, OQS_SIG_sphincs_shake256_256s_simple_length_secret_key, OQS_SIG_sphincs_shake256_256s_simple_length_signature, 0},
};


PQC_OQS_ALGO_TABLE mPqcOqsKemAlgoNameTable[] = {
  {OQS_KEM_alg_bike1_l1_cpa,              PQC_CRYPTO_KEM_NID_BIKE1_L1_CPA},
  {OQS_KEM_alg_bike1_l3_cpa,              PQC_CRYPTO_KEM_NID_BIKE1_L3_CPA},
  {OQS_KEM_alg_bike1_l1_fo,               PQC_CRYPTO_KEM_NID_BIKE1_L1_FO},
  {OQS_KEM_alg_bike1_l3_fo ,              PQC_CRYPTO_KEM_NID_BIKE1_L3_FO},
  {OQS_KEM_alg_classic_mceliece_348864,   PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864,        OQS_KEM_classic_mceliece_348864_length_public_key,   OQS_KEM_classic_mceliece_348864_length_secret_key,   0, OQS_KEM_classic_mceliece_348864_length_ciphertext,   OQS_KEM_classic_mceliece_348864_length_shared_secret},
  {OQS_KEM_alg_classic_mceliece_348864f,  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864F,       OQS_KEM_classic_mceliece_348864f_length_public_key,  OQS_KEM_classic_mceliece_348864f_length_secret_key,  0, OQS_KEM_classic_mceliece_348864f_length_ciphertext,  OQS_KEM_classic_mceliece_348864f_length_shared_secret},
  {OQS_KEM_alg_classic_mceliece_460896,   PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896,        OQS_KEM_classic_mceliece_460896_length_public_key,   OQS_KEM_classic_mceliece_460896_length_secret_key,   0, OQS_KEM_classic_mceliece_460896_length_ciphertext,   OQS_KEM_classic_mceliece_460896_length_shared_secret},
  {OQS_KEM_alg_classic_mceliece_460896f,  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896F,       OQS_KEM_classic_mceliece_460896f_length_public_key,  OQS_KEM_classic_mceliece_460896f_length_secret_key,  0, OQS_KEM_classic_mceliece_460896f_length_ciphertext,  OQS_KEM_classic_mceliece_460896f_length_shared_secret},
  {OQS_KEM_alg_classic_mceliece_6688128,  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128,       OQS_KEM_classic_mceliece_6688128_length_public_key,  OQS_KEM_classic_mceliece_6688128_length_secret_key,  0, OQS_KEM_classic_mceliece_6688128_length_ciphertext,  OQS_KEM_classic_mceliece_6688128_length_shared_secret},
  {OQS_KEM_alg_classic_mceliece_6688128f, PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128F,      OQS_KEM_classic_mceliece_6688128f_length_public_key, OQS_KEM_classic_mceliece_6688128f_length_secret_key, 0, OQS_KEM_classic_mceliece_6688128f_length_ciphertext, OQS_KEM_classic_mceliece_6688128f_length_shared_secret},
  {OQS_KEM_alg_classic_mceliece_6960119,  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119,       OQS_KEM_classic_mceliece_6960119_length_public_key,  OQS_KEM_classic_mceliece_6960119_length_secret_key,  0, OQS_KEM_classic_mceliece_6960119_length_ciphertext,  OQS_KEM_classic_mceliece_6960119_length_shared_secret},
  {OQS_KEM_alg_classic_mceliece_6960119f, PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119F,      OQS_KEM_classic_mceliece_6960119f_length_public_key, OQS_KEM_classic_mceliece_6960119f_length_secret_key, 0, OQS_KEM_classic_mceliece_6960119f_length_ciphertext, OQS_KEM_classic_mceliece_6960119f_length_shared_secret},
  {OQS_KEM_alg_classic_mceliece_8192128,  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128,       OQS_KEM_classic_mceliece_8192128_length_public_key,  OQS_KEM_classic_mceliece_8192128_length_secret_key,  0, OQS_KEM_classic_mceliece_8192128_length_ciphertext,  OQS_KEM_classic_mceliece_8192128_length_shared_secret},
  {OQS_KEM_alg_classic_mceliece_8192128f, PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128F,      OQS_KEM_classic_mceliece_8192128f_length_public_key, OQS_KEM_classic_mceliece_8192128f_length_secret_key, 0, OQS_KEM_classic_mceliece_8192128f_length_ciphertext, OQS_KEM_classic_mceliece_8192128f_length_shared_secret},
  {OQS_KEM_alg_hqc_128,                   PQC_CRYPTO_KEM_NID_HQC_128,                        OQS_KEM_hqc_128_length_public_key,                   OQS_KEM_hqc_128_length_secret_key,                   0, OQS_KEM_hqc_128_length_ciphertext,                   OQS_KEM_hqc_128_length_shared_secret},
  {OQS_KEM_alg_hqc_192,                   PQC_CRYPTO_KEM_NID_HQC_192,                        OQS_KEM_hqc_192_length_public_key,                   OQS_KEM_hqc_192_length_secret_key,                   0, OQS_KEM_hqc_192_length_ciphertext,                   OQS_KEM_hqc_192_length_shared_secret},
  {OQS_KEM_alg_hqc_256,                   PQC_CRYPTO_KEM_NID_HQC_256,                        OQS_KEM_hqc_256_length_public_key,                   OQS_KEM_hqc_256_length_secret_key,                   0, OQS_KEM_hqc_256_length_ciphertext,                   OQS_KEM_hqc_256_length_shared_secret},
  {OQS_KEM_alg_kyber_512,                 PQC_CRYPTO_KEM_NID_KYBER_512,                      OQS_KEM_kyber_512_length_public_key,                 OQS_KEM_kyber_512_length_secret_key,                 0, OQS_KEM_kyber_512_length_ciphertext,                 OQS_KEM_kyber_512_length_shared_secret},
  {OQS_KEM_alg_kyber_768,                 PQC_CRYPTO_KEM_NID_KYBER_768,                      OQS_KEM_kyber_768_length_public_key,                 OQS_KEM_kyber_768_length_secret_key,                 0, OQS_KEM_kyber_768_length_ciphertext,                 OQS_KEM_kyber_768_length_shared_secret},
  {OQS_KEM_alg_kyber_1024,                PQC_CRYPTO_KEM_NID_KYBER_1024,                     OQS_KEM_kyber_1024_length_public_key,                OQS_KEM_kyber_1024_length_secret_key,                0, OQS_KEM_kyber_1024_length_ciphertext,                OQS_KEM_kyber_1024_length_shared_secret},
  {OQS_KEM_alg_kyber_512_90s,             PQC_CRYPTO_KEM_NID_KYBER_512_90S,                  OQS_KEM_kyber_512_90s_length_public_key,             OQS_KEM_kyber_512_90s_length_secret_key,             0, OQS_KEM_kyber_512_90s_length_ciphertext,             OQS_KEM_kyber_512_90s_length_shared_secret},
  {OQS_KEM_alg_kyber_768_90s,             PQC_CRYPTO_KEM_NID_KYBER_768_90S,                  OQS_KEM_kyber_768_90s_length_public_key,             OQS_KEM_kyber_768_90s_length_secret_key,             0, OQS_KEM_kyber_768_90s_length_ciphertext,             OQS_KEM_kyber_768_90s_length_shared_secret},
  {OQS_KEM_alg_kyber_1024_90s,            PQC_CRYPTO_KEM_NID_KYBER_1024_90S,                 OQS_KEM_kyber_1024_90s_length_public_key,            OQS_KEM_kyber_1024_90s_length_secret_key,            0, OQS_KEM_kyber_1024_90s_length_ciphertext,            OQS_KEM_kyber_1024_90s_length_shared_secret},
  {OQS_KEM_alg_ntru_hps2048509,           PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_509,              OQS_KEM_ntru_hps2048509_length_public_key,           OQS_KEM_ntru_hps2048509_length_secret_key,           0, OQS_KEM_ntru_hps2048509_length_ciphertext,           OQS_KEM_ntru_hps2048509_length_shared_secret},
  {OQS_KEM_alg_ntru_hps2048677,           PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_677,              OQS_KEM_ntru_hps2048677_length_public_key,           OQS_KEM_ntru_hps2048677_length_secret_key,           0, OQS_KEM_ntru_hps2048677_length_ciphertext,           OQS_KEM_ntru_hps2048677_length_shared_secret},
  {OQS_KEM_alg_ntru_hps4096821,           PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_821,              OQS_KEM_ntru_hps4096821_length_public_key,           OQS_KEM_ntru_hps4096821_length_secret_key,           0, OQS_KEM_ntru_hps4096821_length_ciphertext,           OQS_KEM_ntru_hps4096821_length_shared_secret},
  {OQS_KEM_alg_ntru_hrss701,              PQC_CRYPTO_KEM_NID_NTRU_HRSS_701,                  OQS_KEM_ntru_hrss701_length_public_key,              OQS_KEM_ntru_hrss701_length_secret_key,              0, OQS_KEM_ntru_hrss701_length_ciphertext,              OQS_KEM_ntru_hrss701_length_shared_secret},
  {OQS_KEM_alg_ntruprime_ntrulpr653,      PQC_CRYPTO_KEM_NID_NTRULPR653,                     OQS_KEM_ntruprime_ntrulpr653_length_public_key,      OQS_KEM_ntruprime_ntrulpr653_length_secret_key,      0, OQS_KEM_ntruprime_ntrulpr653_length_ciphertext,      OQS_KEM_ntruprime_ntrulpr653_length_shared_secret},
  {OQS_KEM_alg_ntruprime_ntrulpr761,      PQC_CRYPTO_KEM_NID_NTRULPR761,                     OQS_KEM_ntruprime_ntrulpr761_length_public_key,      OQS_KEM_ntruprime_ntrulpr761_length_secret_key,      0, OQS_KEM_ntruprime_ntrulpr761_length_ciphertext,      OQS_KEM_ntruprime_ntrulpr761_length_shared_secret},
  {OQS_KEM_alg_ntruprime_ntrulpr857,      PQC_CRYPTO_KEM_NID_NTRULPR857,                     OQS_KEM_ntruprime_ntrulpr857_length_public_key,      OQS_KEM_ntruprime_ntrulpr857_length_secret_key,      0, OQS_KEM_ntruprime_ntrulpr857_length_ciphertext,      OQS_KEM_ntruprime_ntrulpr857_length_shared_secret},
  {OQS_KEM_alg_ntruprime_sntrup653,       PQC_CRYPTO_KEM_NID_SNTRUP653,                      OQS_KEM_ntruprime_sntrup653_length_public_key,       OQS_KEM_ntruprime_sntrup653_length_secret_key,       0, OQS_KEM_ntruprime_sntrup653_length_ciphertext,       OQS_KEM_ntruprime_sntrup653_length_shared_secret},
  {OQS_KEM_alg_ntruprime_sntrup761,       PQC_CRYPTO_KEM_NID_SNTRUP761,                      OQS_KEM_ntruprime_sntrup761_length_public_key,       OQS_KEM_ntruprime_sntrup761_length_secret_key,       0, OQS_KEM_ntruprime_sntrup761_length_ciphertext,       OQS_KEM_ntruprime_sntrup761_length_shared_secret},
  {OQS_KEM_alg_ntruprime_sntrup857,       PQC_CRYPTO_KEM_NID_SNTRUP857,                      OQS_KEM_ntruprime_sntrup857_length_public_key,       OQS_KEM_ntruprime_sntrup857_length_secret_key,       0, OQS_KEM_ntruprime_sntrup857_length_ciphertext,       OQS_KEM_ntruprime_sntrup857_length_shared_secret},
  {OQS_KEM_alg_saber_lightsaber,          PQC_CRYPTO_KEM_NID_LIGHTSABER_KEM,                 OQS_KEM_saber_lightsaber_length_public_key,          OQS_KEM_saber_lightsaber_length_secret_key,          0, OQS_KEM_saber_lightsaber_length_ciphertext,          OQS_KEM_saber_lightsaber_length_shared_secret},
  {OQS_KEM_alg_saber_saber,               PQC_CRYPTO_KEM_NID_SABER_KEM,                      OQS_KEM_saber_saber_length_public_key,               OQS_KEM_saber_saber_length_secret_key,               0, OQS_KEM_saber_saber_length_ciphertext,               OQS_KEM_saber_saber_length_shared_secret},
  {OQS_KEM_alg_saber_firesaber,           PQC_CRYPTO_KEM_NID_FIRESABER_KEM,                  OQS_KEM_saber_firesaber_length_public_key,           OQS_KEM_saber_firesaber_length_secret_key,           0, OQS_KEM_saber_firesaber_length_ciphertext,           OQS_KEM_saber_firesaber_length_shared_secret},
  {OQS_KEM_alg_frodokem_640_aes,          PQC_CRYPTO_KEM_NID_FRODOKEM_640_AES,               OQS_KEM_frodokem_640_aes_length_public_key,          OQS_KEM_frodokem_640_aes_length_secret_key,          0, OQS_KEM_frodokem_640_aes_length_ciphertext,          OQS_KEM_frodokem_640_aes_length_shared_secret},
  {OQS_KEM_alg_frodokem_640_shake,        PQC_CRYPTO_KEM_NID_FRODOKEM_640_SHAKE,             OQS_KEM_frodokem_640_shake_length_public_key,        OQS_KEM_frodokem_640_shake_length_secret_key,        0, OQS_KEM_frodokem_640_shake_length_ciphertext,        OQS_KEM_frodokem_640_shake_length_shared_secret},
  {OQS_KEM_alg_frodokem_976_aes,          PQC_CRYPTO_KEM_NID_FRODOKEM_976_AES,               OQS_KEM_frodokem_976_aes_length_public_key,          OQS_KEM_frodokem_976_aes_length_secret_key,          0, OQS_KEM_frodokem_976_aes_length_ciphertext,          OQS_KEM_frodokem_976_aes_length_shared_secret},
  {OQS_KEM_alg_frodokem_976_shake,        PQC_CRYPTO_KEM_NID_FRODOKEM_976_SHAKE,             OQS_KEM_frodokem_976_shake_length_public_key,        OQS_KEM_frodokem_976_shake_length_secret_key,        0, OQS_KEM_frodokem_976_shake_length_ciphertext,        OQS_KEM_frodokem_976_shake_length_shared_secret},
  {OQS_KEM_alg_frodokem_1344_aes,         PQC_CRYPTO_KEM_NID_FRODOKEM_1344_AES,              OQS_KEM_frodokem_1344_aes_length_public_key,         OQS_KEM_frodokem_1344_aes_length_secret_key,         0, OQS_KEM_frodokem_1344_aes_length_ciphertext,         OQS_KEM_frodokem_1344_aes_length_shared_secret},
  {OQS_KEM_alg_frodokem_1344_shake,       PQC_CRYPTO_KEM_NID_FRODOKEM_1344_SHAKE,            OQS_KEM_frodokem_1344_shake_length_public_key,       OQS_KEM_frodokem_1344_shake_length_secret_key,       0, OQS_KEM_frodokem_1344_shake_length_ciphertext,       OQS_KEM_frodokem_1344_shake_length_shared_secret},
  {OQS_KEM_alg_sidh_p434,                 PQC_CRYPTO_KEM_NID_SIDH_P434,                      OQS_KEM_sike_p434_length_public_key,                 OQS_KEM_sike_p434_length_secret_key,                 0, OQS_KEM_sike_p434_length_ciphertext,                 OQS_KEM_sike_p434_length_shared_secret},
  {OQS_KEM_alg_sidh_p434_compressed,      PQC_CRYPTO_KEM_NID_SIDH_P434_COMPRESSED,           OQS_KEM_sike_p434_compressed_length_public_key,      OQS_KEM_sike_p434_compressed_length_secret_key,      0, OQS_KEM_sike_p434_compressed_length_ciphertext,      OQS_KEM_sike_p434_compressed_length_shared_secret},
  {OQS_KEM_alg_sidh_p503,                 PQC_CRYPTO_KEM_NID_SIDH_P503,                      OQS_KEM_sike_p503_length_public_key,                 OQS_KEM_sike_p503_length_secret_key,                 0, OQS_KEM_sike_p503_length_ciphertext,                 OQS_KEM_sike_p503_length_shared_secret},
  {OQS_KEM_alg_sidh_p503_compressed,      PQC_CRYPTO_KEM_NID_SIDH_P503_COMPRESSED,           OQS_KEM_sike_p503_compressed_length_public_key,      OQS_KEM_sike_p503_compressed_length_secret_key,      0, OQS_KEM_sike_p503_compressed_length_ciphertext,      OQS_KEM_sike_p503_compressed_length_shared_secret},
  {OQS_KEM_alg_sidh_p610,                 PQC_CRYPTO_KEM_NID_SIDH_P610,                      OQS_KEM_sike_p610_length_public_key,                 OQS_KEM_sike_p610_length_secret_key,                 0, OQS_KEM_sike_p610_length_ciphertext,                 OQS_KEM_sike_p610_length_shared_secret},
  {OQS_KEM_alg_sidh_p610_compressed,      PQC_CRYPTO_KEM_NID_SIDH_P610_COMPRESSED,           OQS_KEM_sike_p610_compressed_length_public_key,      OQS_KEM_sike_p610_compressed_length_secret_key,      0, OQS_KEM_sike_p610_compressed_length_ciphertext,      OQS_KEM_sike_p610_compressed_length_shared_secret},
  {OQS_KEM_alg_sidh_p751,                 PQC_CRYPTO_KEM_NID_SIDH_P751,                      OQS_KEM_sike_p751_length_public_key,                 OQS_KEM_sike_p751_length_secret_key,                 0, OQS_KEM_sike_p751_length_ciphertext,                 OQS_KEM_sike_p751_length_shared_secret},
  {OQS_KEM_alg_sidh_p751_compressed,      PQC_CRYPTO_KEM_NID_SIDH_P751_COMPRESSED,           OQS_KEM_sike_p751_compressed_length_public_key,      OQS_KEM_sike_p751_compressed_length_secret_key,      0, OQS_KEM_sike_p751_compressed_length_ciphertext,      OQS_KEM_sike_p751_compressed_length_shared_secret},
  {OQS_KEM_alg_sike_p434,                 PQC_CRYPTO_KEM_NID_SIKE_P434,                      OQS_KEM_sidh_p434_length_public_key,                 OQS_KEM_sidh_p434_length_secret_key,                 0, OQS_KEM_sidh_p434_length_ciphertext,                 OQS_KEM_sidh_p434_length_shared_secret},
  {OQS_KEM_alg_sike_p434_compressed,      PQC_CRYPTO_KEM_NID_SIKE_P434_COMPRESSED,           OQS_KEM_sidh_p434_compressed_length_public_key,      OQS_KEM_sidh_p434_compressed_length_secret_key,      0, OQS_KEM_sidh_p434_compressed_length_ciphertext,      OQS_KEM_sidh_p434_compressed_length_shared_secret},
  {OQS_KEM_alg_sike_p503,                 PQC_CRYPTO_KEM_NID_SIKE_P503,                      OQS_KEM_sidh_p503_length_public_key,                 OQS_KEM_sidh_p503_length_secret_key,                 0, OQS_KEM_sidh_p503_length_ciphertext,                 OQS_KEM_sidh_p503_length_shared_secret},
  {OQS_KEM_alg_sike_p503_compressed,      PQC_CRYPTO_KEM_NID_SIKE_P503_COMPRESSED,           OQS_KEM_sidh_p503_compressed_length_public_key,      OQS_KEM_sidh_p503_compressed_length_secret_key,      0, OQS_KEM_sidh_p503_compressed_length_ciphertext,      OQS_KEM_sidh_p503_compressed_length_shared_secret},
  {OQS_KEM_alg_sike_p610,                 PQC_CRYPTO_KEM_NID_SIKE_P610,                      OQS_KEM_sidh_p610_length_public_key,                 OQS_KEM_sidh_p610_length_secret_key,                 0, OQS_KEM_sidh_p610_length_ciphertext,                 OQS_KEM_sidh_p610_length_shared_secret},
  {OQS_KEM_alg_sike_p610_compressed,      PQC_CRYPTO_KEM_NID_SIKE_P610_COMPRESSED,           OQS_KEM_sidh_p610_compressed_length_public_key,      OQS_KEM_sidh_p610_compressed_length_secret_key,      0, OQS_KEM_sidh_p610_compressed_length_ciphertext,      OQS_KEM_sidh_p610_compressed_length_shared_secret},
  {OQS_KEM_alg_sike_p751,                 PQC_CRYPTO_KEM_NID_SIKE_P751,                      OQS_KEM_sidh_p751_length_public_key,                 OQS_KEM_sidh_p751_length_secret_key,                 0, OQS_KEM_sidh_p751_length_ciphertext,                 OQS_KEM_sidh_p751_length_shared_secret},
  {OQS_KEM_alg_sike_p751_compressed,      PQC_CRYPTO_KEM_NID_SIKE_P751_COMPRESSED,           OQS_KEM_sidh_p751_compressed_length_public_key,      OQS_KEM_sidh_p751_compressed_length_secret_key,      0, OQS_KEM_sidh_p751_compressed_length_ciphertext,      OQS_KEM_sidh_p751_compressed_length_shared_secret},
};

typedef struct {
  OQS_SIG  *OqsSig;
  VOID     *public_key;
  VOID     *secret_key;
} PQC_OQS_SIG;

typedef struct {
  OQS_KEM  *OqsKem;
  VOID     *public_key;
  VOID     *secret_key;
} PQC_OQS_KEM;

PQC_OQS_ALGO_TABLE *
PqcGetOqsAlgoEntry (
  IN   UINTN               Nid,
  IN   PQC_OQS_ALGO_TABLE  *Table,
  IN   UINTN               TableCount
  )
{
  UINT8   Index;

  for (Index = 0; Index < TableCount; Index++) {
    if (Table[Index].Nid == Nid) {
      return &Table[Index];
    }
  }
  return NULL;
}

PQC_OQS_ALGO_TABLE *
PqcGetOqsSigAlgoEntry (
  IN UINTN  Nid
  )
{
  return PqcGetOqsAlgoEntry (Nid, mPqcOqsSigAlgoNameTable, ARRAY_SIZE(mPqcOqsSigAlgoNameTable));
}

PQC_OQS_ALGO_TABLE *
PqcGetOqsKemAlgoEntry (
  IN UINTN  Nid
  )
{
  return PqcGetOqsAlgoEntry (Nid, mPqcOqsKemAlgoNameTable, ARRAY_SIZE(mPqcOqsKemAlgoNameTable));
}

/**
  This function returns the PQC SIG algorithm size.

  @param Nid cipher NID

  @return PQC SIG algorithm size.
**/
UINTN
EFIAPI
PqcGetOqsSigSignatureSize (
  IN UINTN  Nid
  )
{
  PQC_OQS_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = PqcGetOqsSigAlgoEntry (Nid);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return (UINT32)AlgoEntry->length_signature;
}

/**
  This function returns the PQC SIG algorithm size.

  @param Nid cipher NID

  @return PQC SIG algorithm size.
**/
UINTN
EFIAPI
PqcGetOqsSigPrivKeySize (
  IN UINTN  Nid
  )
{
  PQC_OQS_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = PqcGetOqsSigAlgoEntry (Nid);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return (UINT32)AlgoEntry->length_secret_key;
}

/**
  This function returns the PQC SIG algorithm size.

  @param Nid cipher NID

  @return PQC SIG algorithm size.
**/
UINTN
EFIAPI
PqcGetOqsSigPubKeySize (
  IN UINTN  Nid
  )
{
  PQC_OQS_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = PqcGetOqsSigAlgoEntry (Nid);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return (UINT32)AlgoEntry->length_public_key;
}

/**
  This function returns the PQC KEM algorithm key size.

  @param Nid cipher NID

  @return PQC KEM algorithm key size.
**/
UINTN
EFIAPI
PqcGetOqsKemSharedKeySize (
  IN UINTN  Nid
  )
{
  PQC_OQS_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = PqcGetOqsKemAlgoEntry (Nid);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return (UINT32)AlgoEntry->length_shared_secret;
}

/**
  This function returns the PQC KEM algorithm key size.

  @param Nid cipher NID

  @return PQC KEM algorithm key size.
**/
UINTN
EFIAPI
PqcGetOqsKemCipherTextSize (
  IN UINTN  Nid
  )
{
  PQC_OQS_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = PqcGetOqsKemAlgoEntry (Nid);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return (UINT32)AlgoEntry->length_ciphertext;
}

/**
  This function returns the PQC KEM algorithm key size.

  @param Nid cipher NID

  @return PQC KEM algorithm key size.
**/
UINTN
EFIAPI
PqcGetOqsKemPrivKeySize (
  IN UINTN  Nid
  )
{
  PQC_OQS_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = PqcGetOqsKemAlgoEntry (Nid);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return (UINT32)AlgoEntry->length_secret_key;
}

/**
  This function returns the PQC KEM algorithm key size.

  @param Nid cipher NID

  @return PQC KEM algorithm key size.
**/
UINTN
EFIAPI
PqcGetOqsKemPubKeySize (
  IN UINTN  Nid
  )
{
  PQC_OQS_ALGO_TABLE  *AlgoEntry;

  AlgoEntry = PqcGetOqsKemAlgoEntry (Nid);
  if (AlgoEntry == NULL) {
    return 0;
  }
  return (UINT32)AlgoEntry->length_public_key;
}

/**
  Allocates and Initializes one PQC SIG Context for subsequent use.

  @param Nid cipher NID

  @return  Pointer to the PQC SIG Context that has been initialized.
**/
VOID *
EFIAPI
PqcSigNewByNid (
  IN UINTN  Nid
  )
{
  PQC_OQS_ALGO_TABLE  *AlgoEntry;
  PQC_OQS_SIG         *OqsSig;

  AlgoEntry = PqcGetOqsSigAlgoEntry (Nid);
  if (AlgoEntry == NULL) {
    return NULL;
  }
  if (OQS_SIG_alg_is_enabled (AlgoEntry->Name) == 0) {
    return NULL;
  }
  OqsSig = malloc (sizeof(PQC_OQS_SIG));
  if (OqsSig == NULL) {
    return NULL;
  }
  OqsSig->OqsSig = OQS_SIG_new (AlgoEntry->Name);
  if (OqsSig->OqsSig == NULL) {
    free (OqsSig);
    return NULL;
  }
  OqsSig->public_key = NULL;
  OqsSig->secret_key = NULL;

  return OqsSig;
}

/**
  Generate key pairs.

  @param  Context                      Pointer to the PQC SIG context.

  @retval  TRUE   Key pairs are generated.
  @retval  FALSE  Fail to generate the key pairs.
**/
BOOLEAN
EFIAPI
PqcSigGenerateKey (
  IN   VOID         *Context
  )
{
  PQC_OQS_SIG         *OqsSig;
  OQS_STATUS           Status;

  OqsSig = Context;
  if (OqsSig->public_key != NULL) {
    free (OqsSig->public_key);
  }
  OqsSig->public_key = malloc (OqsSig->OqsSig->length_public_key);
  if (OqsSig->public_key == NULL) {
    return FALSE;
  }
  if (OqsSig->secret_key != NULL) {
    ZeroMem (OqsSig->secret_key, OqsSig->OqsSig->length_secret_key);
    free (OqsSig->secret_key);
  }
  OqsSig->secret_key = malloc (OqsSig->OqsSig->length_secret_key);
  if (OqsSig->secret_key == NULL) {
    free (OqsSig->public_key);
    OqsSig->public_key = NULL;
    return FALSE;
  }

  Status = OqsSig->OqsSig->keypair (OqsSig->public_key, OqsSig->secret_key);
  if (Status != OQS_SUCCESS) {
    free (OqsSig->public_key);
    OqsSig->public_key = NULL;
    free (OqsSig->secret_key);
    OqsSig->secret_key = NULL;
    return FALSE;
  }

  return TRUE;
}

/**
  Retrieve the PQC Public Key from raw data.

  @param  Context                      Pointer to the PQC SIG context.
  @param  RawData                      Pointer to raw data buffer to hold the public key.
  @param  RawDataSize                  Size of the raw data buffer in bytes.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from raw data buffer.
**/
BOOLEAN
EFIAPI
PqcSigSetPublicKey (
  IN   VOID         *Context,
  IN   CONST UINT8  *RawData,
  IN   UINTN        RawDataSize
  )
{
  PQC_OQS_SIG         *OqsSig;

  OqsSig = Context;
  if (RawDataSize != OqsSig->OqsSig->length_public_key) {
    return FALSE;
  }
  if (OqsSig->public_key != NULL) {
    free (OqsSig->public_key);
  }
  OqsSig->public_key = malloc (OqsSig->OqsSig->length_public_key);
  if (OqsSig->public_key == NULL) {
    return FALSE;
  }
  CopyMem (OqsSig->public_key, RawData, RawDataSize);

  return TRUE;
}

/**
  Release the specified PQC SIG context.

  @param  Context                      Pointer to the PQC SIG context.
**/
VOID
EFIAPI
PqcSigFree (
  IN   VOID         *Context
  )
{
  PQC_OQS_SIG         *OqsSig;

  OqsSig = Context;
  if (OqsSig->public_key != NULL) {
    free (OqsSig->public_key);
  }
  if (OqsSig->secret_key != NULL) {
    ZeroMem (OqsSig->secret_key, OqsSig->OqsSig->length_secret_key);
    free (OqsSig->secret_key);
  }
  OQS_SIG_free (OqsSig->OqsSig);
  free (OqsSig);
}

/**
  Verifies the PQC signature.
a
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
PqcSigVerify (
  IN  VOID         *Context,
  IN  CONST UINT8  *Message,
  IN  UINTN        MessageSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  )
{
  PQC_OQS_SIG         *OqsSig;
  OQS_STATUS           Status;

  OqsSig = Context;
  Status = OqsSig->OqsSig->verify (Message, MessageSize, Signature, SigSize, OqsSig->public_key);
  if (Status != OQS_SUCCESS) {
    return FALSE;
  }
  return TRUE;
}

/**
  Retrieve the Private Key from the raw data.

  @param  Context                      Pointer to the PQC SIG context.
  @param  RawData                      Pointer to raw data buffer to hold the private key.
  @param  RawDataSize                  Size of the raw data buffer in bytes.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid raw data buffer.
**/
BOOLEAN
EFIAPI
PqcSigSetPrivateKey (
  IN   VOID         *Context,
  IN   CONST UINT8  *RawData,
  IN   UINTN        RawDataSize
  )
{
  PQC_OQS_SIG         *OqsSig;

  OqsSig = Context;
  if (RawDataSize != OqsSig->OqsSig->length_secret_key) {
    return FALSE;
  }
  if (OqsSig->secret_key != NULL) {
    ZeroMem (OqsSig->secret_key, OqsSig->OqsSig->length_secret_key);
    free (OqsSig->secret_key);
  }
  OqsSig->secret_key = malloc (OqsSig->OqsSig->length_secret_key);
  if (OqsSig->secret_key == NULL) {
    return FALSE;
  }
  CopyMem (OqsSig->secret_key, RawData, RawDataSize);

  return TRUE;
}

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

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
PqcSigSign (
  IN      VOID         *Context,
  IN      CONST UINT8  *Message,
  IN      UINTN        MessageSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  PQC_OQS_SIG         *OqsSig;
  OQS_STATUS           Status;

  OqsSig = Context;
  Status = OqsSig->OqsSig->sign (Signature, SigSize, Message, MessageSize, OqsSig->secret_key);
  if (Status != OQS_SUCCESS) {
    return FALSE;
  }
  return TRUE;
}

/**
  Allocates and Initializes one PQC KEM Context for subsequent use.

  @param  PqcKemAlgo                   PqcKemAlgo

  @return  Pointer to the PQC KEM Context that has been initialized.
**/
VOID *
EFIAPI
PqcKemNewByNid (
  IN UINTN  Nid
  )
{
  PQC_OQS_ALGO_TABLE  *AlgoEntry;
  PQC_OQS_KEM         *OqsKem;

  AlgoEntry = PqcGetOqsKemAlgoEntry (Nid);
  if (AlgoEntry == NULL) {
    return NULL;
  }
  if (OQS_KEM_alg_is_enabled (AlgoEntry->Name) == 0) {
    return NULL;
  }
  OqsKem = malloc (sizeof(PQC_OQS_KEM));
  if (OqsKem == NULL) {
    return NULL;
  }
  OqsKem->OqsKem = OQS_KEM_new (AlgoEntry->Name);
  if (OqsKem->OqsKem == NULL) {
    free (OqsKem);
    return NULL;
  }
  OqsKem->secret_key = NULL;
  OqsKem->public_key = NULL;

  return OqsKem;
}

/**
  Release the specified PQC KEM context.

  @param  Context                      Pointer to the PQC KEM context.
**/
VOID
EFIAPI
PqcKemFree (
  IN      VOID         *Context
  )
{
  PQC_OQS_KEM         *OqsKem;

  OqsKem = Context;
  if (OqsKem->public_key != NULL) {
    free (OqsKem->public_key);
  }
  if (OqsKem->secret_key != NULL) {
    ZeroMem (OqsKem->secret_key, OqsKem->OqsKem->length_secret_key);
    free (OqsKem->secret_key);
  }
  OQS_KEM_free (OqsKem->OqsKem);
  free (OqsKem);
}

/**
  Generate key pairs.

  @param  Context                      Pointer to the PQC KEM context.

  @retval  TRUE   Key pairs are generated.
  @retval  FALSE  Fail to generate the key pairs.
**/
BOOLEAN
EFIAPI
PqcKemGenerateKey (
  IN   VOID         *Context
  )
{
  PQC_OQS_KEM         *OqsKem;
  OQS_STATUS           Status;

  OqsKem = Context;
  if (OqsKem->public_key != NULL) {
    free (OqsKem->public_key);
  }
  OqsKem->public_key = malloc (OqsKem->OqsKem->length_public_key);
  if (OqsKem->public_key == NULL) {
    return FALSE;
  }
  if (OqsKem->secret_key != NULL) {
    ZeroMem (OqsKem->secret_key, OqsKem->OqsKem->length_secret_key);
    free (OqsKem->secret_key);
  }
  OqsKem->secret_key = malloc (OqsKem->OqsKem->length_secret_key);
  if (OqsKem->secret_key == NULL) {
    free (OqsKem->public_key);
    OqsKem->public_key = NULL;
    return FALSE;
  }

  Status = OqsKem->OqsKem->keypair (OqsKem->public_key, OqsKem->secret_key);
  if (Status != OQS_SUCCESS) {
    free (OqsKem->public_key);
    OqsKem->public_key = NULL;
    free (OqsKem->secret_key);
    OqsKem->secret_key = NULL;
    return FALSE;
  }

  return TRUE;
}

/**
  Retrieve the PQC Public Key.

  @param  Context                      Pointer to the PQC SIG context.
  @param  PublicKey                    Pointer to the buffer to receive generated public key.
  @param  PublicKeySize                On input, the size of PublicKey buffer in bytes.
                                       On output, the size of data returned in PublicKey buffer in bytes.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from raw data buffer.
**/
BOOLEAN
EFIAPI
PqcKemGetPublicKey (
  IN      VOID         *Context,
  OUT     UINT8        *PublicKey,
  IN OUT  UINTN        *PublicKeySize
  )
{
  PQC_OQS_KEM         *OqsKem;

  OqsKem = Context;

  if (*PublicKeySize < OqsKem->OqsKem->length_public_key) {
    *PublicKeySize = OqsKem->OqsKem->length_public_key;
    return FALSE;
  }
  *PublicKeySize = OqsKem->OqsKem->length_public_key;

  CopyMem (PublicKey, OqsKem->public_key, OqsKem->OqsKem->length_public_key);

  return TRUE;
}

/**
  Generate shared key and return the encap data for the shared key with peer public key.

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
PqcKemEncap (
  IN OUT  VOID         *Context,
  IN      CONST UINT8  *PeerPublic,
  IN      UINTN        PeerPublicSize,
  OUT     UINT8        *SharedKey,
  IN OUT  UINTN        *SharedKeySize,
  OUT     UINT8        *CipherText,
  IN OUT  UINTN        *CipherTextSize
  )
{
  PQC_OQS_KEM         *OqsKem;
  OQS_STATUS           Status;

  OqsKem = Context;

  if (PeerPublicSize != OqsKem->OqsKem->length_public_key) {
    return FALSE;
  }
  if (*SharedKeySize < OqsKem->OqsKem->length_shared_secret) {
    *SharedKeySize = OqsKem->OqsKem->length_shared_secret;
    return FALSE;
  }
  *SharedKeySize = OqsKem->OqsKem->length_shared_secret;

  if (*CipherTextSize < OqsKem->OqsKem->length_ciphertext) {
    *CipherTextSize = OqsKem->OqsKem->length_ciphertext;
    return FALSE;
  }
  *CipherTextSize = OqsKem->OqsKem->length_ciphertext;

  Status = OqsKem->OqsKem->encaps (CipherText, SharedKey, PeerPublic);
  if (Status != OQS_SUCCESS) {
    return FALSE;
  }

  return TRUE;
}

/**
  Decap the cipher text to shared key with private key.

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
PqcKemDecap (
  IN OUT  VOID         *Context,
  OUT     UINT8        *SharedKey,
  IN OUT  UINTN        *SharedKeySize,
  IN      UINT8        *CipherText,
  IN      UINTN        CipherTextSize
  )
{
  PQC_OQS_KEM         *OqsKem;
  OQS_STATUS           Status;

  OqsKem = Context;

  if (CipherTextSize != OqsKem->OqsKem->length_ciphertext) {
    return FALSE;
  }
  if (*SharedKeySize < OqsKem->OqsKem->length_shared_secret) {
    *SharedKeySize = OqsKem->OqsKem->length_shared_secret;
    return FALSE;
  }
  *SharedKeySize = OqsKem->OqsKem->length_shared_secret;

  Status = OqsKem->OqsKem->decaps (SharedKey, CipherText, OqsKem->secret_key);
  if (Status != OQS_SUCCESS) {
    return FALSE;
  }
  return TRUE;
}

