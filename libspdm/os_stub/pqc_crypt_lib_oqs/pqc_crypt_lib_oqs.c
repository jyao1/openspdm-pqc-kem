/** @file
  common library.
  It follows the Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <library/pqc_crypt_lib.h>
#include <oqs/sig.h>
#include <oqs/sig_dilithium.h>
#include <oqs/sig_falcon.h>
#include <oqs/sig_picnic.h>
#include <oqs/sig_rainbow.h>
#include <oqs/sig_sphincs.h>
#include <oqs/kem.h>
#include <oqs/kem_bike.h>
#include <oqs/kem_classic_mceliece.h>
#include <oqs/kem_frodokem.h>
#include <oqs/kem_hqc.h>
#include <oqs/kem_kyber.h>
#include <oqs/kem_ntru.h>
#include <oqs/kem_ntruprime.h>
#include <oqs/kem_saber.h>
#include <oqs/kem_sike.h>

pqc_oqs_algo_table_t m_pqc_oqs_sig_algo_name_table[] = {
  {OQS_SIG_alg_dilithium_2,                  PQC_CRYPTO_SIG_NID_DILITHIUM_2,                        OQS_SIG_dilithium_2_length_public_key,                  OQS_SIG_dilithium_2_length_secret_key,                  OQS_SIG_dilithium_2_length_signature, 0},
  {OQS_SIG_alg_dilithium_3,                  PQC_CRYPTO_SIG_NID_DILITHIUM_3,                        OQS_SIG_dilithium_3_length_public_key,                  OQS_SIG_dilithium_3_length_secret_key,                  OQS_SIG_dilithium_3_length_signature, 0},
  {OQS_SIG_alg_dilithium_5,                  PQC_CRYPTO_SIG_NID_DILITHIUM_5,                        OQS_SIG_dilithium_5_length_public_key,                  OQS_SIG_dilithium_5_length_secret_key,                  OQS_SIG_dilithium_5_length_signature, 0},
  {OQS_SIG_alg_dilithium_2_aes,              PQC_CRYPTO_SIG_NID_DILITHIUM_2_AES,                    OQS_SIG_dilithium_2_aes_length_public_key,              OQS_SIG_dilithium_2_aes_length_secret_key,              OQS_SIG_dilithium_2_aes_length_signature, 0},
  {OQS_SIG_alg_dilithium_3_aes,              PQC_CRYPTO_SIG_NID_DILITHIUM_3_AES,                    OQS_SIG_dilithium_3_aes_length_public_key,              OQS_SIG_dilithium_3_aes_length_secret_key,              OQS_SIG_dilithium_3_aes_length_signature, 0},
  {OQS_SIG_alg_dilithium_5_aes,              PQC_CRYPTO_SIG_NID_DILITHIUM_5_AES,                    OQS_SIG_dilithium_5_aes_length_public_key,              OQS_SIG_dilithium_5_aes_length_secret_key,              OQS_SIG_dilithium_5_aes_length_signature, 0},
  {OQS_SIG_alg_falcon_512,                   PQC_CRYPTO_SIG_NID_FALCON_512,                         OQS_SIG_falcon_512_length_public_key,                   OQS_SIG_falcon_512_length_secret_key,                   OQS_SIG_falcon_512_length_signature, 0},
  {OQS_SIG_alg_falcon_1024,                  PQC_CRYPTO_SIG_NID_FALCON_1024,                        OQS_SIG_falcon_1024_length_public_key,                  OQS_SIG_falcon_1024_length_secret_key,                  OQS_SIG_falcon_1024_length_signature, 0},
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


pqc_oqs_algo_table_t m_pqc_oqs_kem_algo_name_table[] = {
#if defined OQS_ENABLE_KEM_BIKE
  {OQS_KEM_alg_bike1_l1_cpa,              PQC_CRYPTO_KEM_NID_BIKE1_L1_CPA,                   OQS_KEM_bike1_l1_cpa_length_public_key,              OQS_KEM_bike1_l1_cpa_length_secret_key,              0, OQS_KEM_bike1_l1_cpa_length_ciphertext,              OQS_KEM_bike1_l1_cpa_length_shared_secret},
  {OQS_KEM_alg_bike1_l3_cpa,              PQC_CRYPTO_KEM_NID_BIKE1_L3_CPA,                   OQS_KEM_bike1_l3_cpa_length_public_key,              OQS_KEM_bike1_l3_cpa_length_secret_key,              0, OQS_KEM_bike1_l3_cpa_length_ciphertext,              OQS_KEM_bike1_l3_cpa_length_shared_secret},
  {OQS_KEM_alg_bike1_l1_fo,               PQC_CRYPTO_KEM_NID_BIKE1_L1_FO,                    OQS_KEM_bike1_l1_fo_length_public_key,               OQS_KEM_bike1_l1_fo_length_secret_key,               0, OQS_KEM_bike1_l1_fo_length_ciphertext,               OQS_KEM_bike1_l1_fo_length_shared_secret},
  {OQS_KEM_alg_bike1_l3_fo ,              PQC_CRYPTO_KEM_NID_BIKE1_L3_FO,                    OQS_KEM_bike1_l3_fo_length_public_key,               OQS_KEM_bike1_l3_fo_length_secret_key,               0, OQS_KEM_bike1_l3_fo_length_ciphertext,               OQS_KEM_bike1_l3_fo_length_shared_secret},
#endif
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
  {OQS_KEM_alg_sidh_p434,                 PQC_CRYPTO_KEM_NID_SIDH_P434,                      OQS_KEM_sidh_p434_length_public_key,                 OQS_KEM_sidh_p434_length_secret_key,                 0, OQS_KEM_sidh_p434_length_ciphertext,                 OQS_KEM_sidh_p434_length_shared_secret},
  {OQS_KEM_alg_sidh_p434_compressed,      PQC_CRYPTO_KEM_NID_SIDH_P434_COMPRESSED,           OQS_KEM_sidh_p434_compressed_length_public_key,      OQS_KEM_sidh_p434_compressed_length_secret_key,      0, OQS_KEM_sidh_p434_compressed_length_ciphertext,      OQS_KEM_sidh_p434_compressed_length_shared_secret},
  {OQS_KEM_alg_sidh_p503,                 PQC_CRYPTO_KEM_NID_SIDH_P503,                      OQS_KEM_sidh_p503_length_public_key,                 OQS_KEM_sidh_p503_length_secret_key,                 0, OQS_KEM_sidh_p503_length_ciphertext,                 OQS_KEM_sidh_p503_length_shared_secret},
  {OQS_KEM_alg_sidh_p503_compressed,      PQC_CRYPTO_KEM_NID_SIDH_P503_COMPRESSED,           OQS_KEM_sidh_p503_compressed_length_public_key,      OQS_KEM_sidh_p503_compressed_length_secret_key,      0, OQS_KEM_sidh_p503_compressed_length_ciphertext,      OQS_KEM_sidh_p503_compressed_length_shared_secret},
  {OQS_KEM_alg_sidh_p610,                 PQC_CRYPTO_KEM_NID_SIDH_P610,                      OQS_KEM_sidh_p610_length_public_key,                 OQS_KEM_sidh_p610_length_secret_key,                 0, OQS_KEM_sidh_p610_length_ciphertext,                 OQS_KEM_sidh_p610_length_shared_secret},
  {OQS_KEM_alg_sidh_p610_compressed,      PQC_CRYPTO_KEM_NID_SIDH_P610_COMPRESSED,           OQS_KEM_sidh_p610_compressed_length_public_key,      OQS_KEM_sidh_p610_compressed_length_secret_key,      0, OQS_KEM_sidh_p610_compressed_length_ciphertext,      OQS_KEM_sidh_p610_compressed_length_shared_secret},
  {OQS_KEM_alg_sidh_p751,                 PQC_CRYPTO_KEM_NID_SIDH_P751,                      OQS_KEM_sidh_p751_length_public_key,                 OQS_KEM_sidh_p751_length_secret_key,                 0, OQS_KEM_sidh_p751_length_ciphertext,                 OQS_KEM_sidh_p751_length_shared_secret},
  {OQS_KEM_alg_sidh_p751_compressed,      PQC_CRYPTO_KEM_NID_SIDH_P751_COMPRESSED,           OQS_KEM_sidh_p751_compressed_length_public_key,      OQS_KEM_sidh_p751_compressed_length_secret_key,      0, OQS_KEM_sidh_p751_compressed_length_ciphertext,      OQS_KEM_sidh_p751_compressed_length_shared_secret},
  {OQS_KEM_alg_sike_p434,                 PQC_CRYPTO_KEM_NID_SIKE_P434,                      OQS_KEM_sike_p434_length_public_key,                 OQS_KEM_sike_p434_length_secret_key,                 0, OQS_KEM_sike_p434_length_ciphertext,                 OQS_KEM_sike_p434_length_shared_secret},
  {OQS_KEM_alg_sike_p434_compressed,      PQC_CRYPTO_KEM_NID_SIKE_P434_COMPRESSED,           OQS_KEM_sike_p434_compressed_length_public_key,      OQS_KEM_sike_p434_compressed_length_secret_key,      0, OQS_KEM_sike_p434_compressed_length_ciphertext,      OQS_KEM_sike_p434_compressed_length_shared_secret},
  {OQS_KEM_alg_sike_p503,                 PQC_CRYPTO_KEM_NID_SIKE_P503,                      OQS_KEM_sike_p503_length_public_key,                 OQS_KEM_sike_p503_length_secret_key,                 0, OQS_KEM_sike_p503_length_ciphertext,                 OQS_KEM_sike_p503_length_shared_secret},
  {OQS_KEM_alg_sike_p503_compressed,      PQC_CRYPTO_KEM_NID_SIKE_P503_COMPRESSED,           OQS_KEM_sike_p503_compressed_length_public_key,      OQS_KEM_sike_p503_compressed_length_secret_key,      0, OQS_KEM_sike_p503_compressed_length_ciphertext,      OQS_KEM_sike_p503_compressed_length_shared_secret},
  {OQS_KEM_alg_sike_p610,                 PQC_CRYPTO_KEM_NID_SIKE_P610,                      OQS_KEM_sike_p610_length_public_key,                 OQS_KEM_sike_p610_length_secret_key,                 0, OQS_KEM_sike_p610_length_ciphertext,                 OQS_KEM_sike_p610_length_shared_secret},
  {OQS_KEM_alg_sike_p610_compressed,      PQC_CRYPTO_KEM_NID_SIKE_P610_COMPRESSED,           OQS_KEM_sike_p610_compressed_length_public_key,      OQS_KEM_sike_p610_compressed_length_secret_key,      0, OQS_KEM_sike_p610_compressed_length_ciphertext,      OQS_KEM_sike_p610_compressed_length_shared_secret},
  {OQS_KEM_alg_sike_p751,                 PQC_CRYPTO_KEM_NID_SIKE_P751,                      OQS_KEM_sike_p751_length_public_key,                 OQS_KEM_sike_p751_length_secret_key,                 0, OQS_KEM_sike_p751_length_ciphertext,                 OQS_KEM_sike_p751_length_shared_secret},
  {OQS_KEM_alg_sike_p751_compressed,      PQC_CRYPTO_KEM_NID_SIKE_P751_COMPRESSED,           OQS_KEM_sike_p751_compressed_length_public_key,      OQS_KEM_sike_p751_compressed_length_secret_key,      0, OQS_KEM_sike_p751_compressed_length_ciphertext,      OQS_KEM_sike_p751_compressed_length_shared_secret},
};

typedef struct {
  OQS_SIG  *oqs_sig;
  void     *public_key;
  void     *secret_key;
} pqc_oqs_sig_t;

typedef struct {
  OQS_KEM  *oqs_kem;
  void     *public_key;
  void     *secret_key;
} pqc_oqs_kem_t;

pqc_oqs_algo_table_t *
pqc_get_oqs_algo_entry (
  IN   uintn               nid,
  IN   pqc_oqs_algo_table_t  *table,
  IN   uintn               table_count
  )
{
  uint8   index;

  for (index = 0; index < table_count; index++) {
    if (table[index].nid == nid) {
      return &table[index];
    }
  }
  return NULL;
}

pqc_oqs_algo_table_t *
pqc_get_oqs_sig_algo_entry (
  IN uintn  nid
  )
{
  return pqc_get_oqs_algo_entry (nid, m_pqc_oqs_sig_algo_name_table, ARRAY_SIZE(m_pqc_oqs_sig_algo_name_table));
}

pqc_oqs_algo_table_t *
pqc_get_oqs_kem_algo_entry (
  IN uintn  nid
  )
{
  return pqc_get_oqs_algo_entry (nid, m_pqc_oqs_kem_algo_name_table, ARRAY_SIZE(m_pqc_oqs_kem_algo_name_table));
}

/**
  This function returns the PQC SIG algorithm name.

  @param nid cipher NID

  @return PQC SIG algorithm name.
**/
char *
pqc_get_oqs_sig_name (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;

  algo_entry = pqc_get_oqs_sig_algo_entry (nid);
  if (algo_entry == NULL) {
    return 0;
  }
  return algo_entry->name;
}

/**
  This function returns the PQC SIG algorithm size.

  @param nid cipher NID

  @return PQC SIG algorithm size.
**/
uintn
pqc_get_oqs_sig_signature_size (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;

  algo_entry = pqc_get_oqs_sig_algo_entry (nid);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)algo_entry->length_signature;
}

/**
  This function returns the PQC SIG algorithm size.

  @param nid cipher NID

  @return PQC SIG algorithm size.
**/
uintn
pqc_get_oqs_sig_private_key_size (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;

  algo_entry = pqc_get_oqs_sig_algo_entry (nid);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)algo_entry->length_secret_key;
}

/**
  This function returns the PQC SIG algorithm size.

  @param nid cipher NID

  @return PQC SIG algorithm size.
**/
uintn
pqc_get_oqs_sig_public_key_size (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;

  algo_entry = pqc_get_oqs_sig_algo_entry (nid);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)algo_entry->length_public_key;
}

/**
  This function returns the PQC KEM algorithm name.

  @param nid cipher NID

  @return PQC KEM algorithm name.
**/
char *
pqc_get_oqs_kem_name (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;

  algo_entry = pqc_get_oqs_kem_algo_entry (nid);
  if (algo_entry == NULL) {
    return 0;
  }
  return algo_entry->name;
}

/**
  This function returns the PQC KEM algorithm key size.

  @param nid cipher NID

  @return PQC KEM algorithm key size.
**/
uintn
pqc_get_oqs_kem_shared_key_size (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;

  algo_entry = pqc_get_oqs_kem_algo_entry (nid);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)algo_entry->length_shared_secret;
}

/**
  This function returns the PQC KEM algorithm key size.

  @param nid cipher NID

  @return PQC KEM algorithm key size.
**/
uintn
pqc_get_oqs_kem_cipher_text_size (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;

  algo_entry = pqc_get_oqs_kem_algo_entry (nid);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)algo_entry->length_ciphertext;
}

/**
  This function returns the PQC KEM algorithm key size.

  @param nid cipher NID

  @return PQC KEM algorithm key size.
**/
uintn
pqc_get_oqs_kem_private_key_size (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;

  algo_entry = pqc_get_oqs_kem_algo_entry (nid);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)algo_entry->length_secret_key;
}

/**
  This function returns the PQC KEM algorithm key size.

  @param nid cipher NID

  @return PQC KEM algorithm key size.
**/
uintn
pqc_get_oqs_kem_public_key_size (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;

  algo_entry = pqc_get_oqs_kem_algo_entry (nid);
  if (algo_entry == NULL) {
    return 0;
  }
  return (uint32)algo_entry->length_public_key;
}

/**
  Allocates and Initializes one PQC SIG context for subsequent use.

  @param nid cipher NID

  @return  Pointer to the PQC SIG context that has been initialized.
**/
void *
pqc_sig_new_by_nid (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;
  pqc_oqs_sig_t         *oqs_sig;

  algo_entry = pqc_get_oqs_sig_algo_entry (nid);
  if (algo_entry == NULL) {
    return NULL;
  }
  if (OQS_SIG_alg_is_enabled (algo_entry->name) == 0) {
    return NULL;
  }
  oqs_sig = malloc (sizeof(pqc_oqs_sig_t));
  if (oqs_sig == NULL) {
    return NULL;
  }
  oqs_sig->oqs_sig = OQS_SIG_new (algo_entry->name);
  if (oqs_sig->oqs_sig == NULL) {
    free (oqs_sig);
    return NULL;
  }
  oqs_sig->public_key = NULL;
  oqs_sig->secret_key = NULL;

  return oqs_sig;
}

/**
  Generate key pairs.

  @param  context                      Pointer to the PQC SIG context.

  @retval  TRUE   Key pairs are generated.
  @retval  FALSE  Fail to generate the key pairs.
**/
boolean
pqc_sig_generate_key (
  IN   void         *context
  )
{
  pqc_oqs_sig_t         *oqs_sig;
  OQS_STATUS           status;

  oqs_sig = context;
  if (oqs_sig->public_key != NULL) {
    free (oqs_sig->public_key);
  }
  oqs_sig->public_key = malloc (oqs_sig->oqs_sig->length_public_key);
  if (oqs_sig->public_key == NULL) {
    return FALSE;
  }
  if (oqs_sig->secret_key != NULL) {
    zero_mem (oqs_sig->secret_key, oqs_sig->oqs_sig->length_secret_key);
    free (oqs_sig->secret_key);
  }
  oqs_sig->secret_key = malloc (oqs_sig->oqs_sig->length_secret_key);
  if (oqs_sig->secret_key == NULL) {
    free (oqs_sig->public_key);
    oqs_sig->public_key = NULL;
    return FALSE;
  }

  status = oqs_sig->oqs_sig->keypair (oqs_sig->public_key, oqs_sig->secret_key);
  if (status != OQS_SUCCESS) {
    free (oqs_sig->public_key);
    oqs_sig->public_key = NULL;
    free (oqs_sig->secret_key);
    oqs_sig->secret_key = NULL;
    return FALSE;
  }

  return TRUE;
}

/**
  Retrieve the PQC Public Key from raw data.

  @param  context                      Pointer to the PQC SIG context.
  @param  raw_data                      Pointer to raw data buffer to hold the public key.
  @param  raw_data_size                  Size of the raw data buffer in bytes.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from raw data buffer.
**/
boolean
pqc_sig_set_public_key (
  IN   void         *context,
  IN   const uint8  *raw_data,
  IN   uintn        raw_data_size
  )
{
  pqc_oqs_sig_t         *oqs_sig;

  oqs_sig = context;
  if (raw_data_size != oqs_sig->oqs_sig->length_public_key) {
    return FALSE;
  }
  if (oqs_sig->public_key != NULL) {
    free (oqs_sig->public_key);
  }
  oqs_sig->public_key = malloc (oqs_sig->oqs_sig->length_public_key);
  if (oqs_sig->public_key == NULL) {
    return FALSE;
  }
  copy_mem (oqs_sig->public_key, raw_data, raw_data_size);

  return TRUE;
}

/**
  Retrieve the PQC Public Key from raw data.

  @param  context                      Pointer to the PQC SIG context.
  @param  raw_data                      Pointer to raw data buffer to hold the public key.
  @param  raw_data_size                  Size of the raw data buffer in bytes.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from raw data buffer.
**/
boolean
pqc_sig_get_public_key (
  IN   void         *context,
  IN   uint8        *raw_data,
  IN   uintn        raw_data_size
  )
{
  pqc_oqs_sig_t         *oqs_sig;

  oqs_sig = context;
  if (raw_data_size != oqs_sig->oqs_sig->length_public_key) {
    return FALSE;
  }
  if (oqs_sig->public_key == NULL) {
    return FALSE;
  }
  copy_mem (raw_data, oqs_sig->public_key, raw_data_size);

  return TRUE;
}

/**
  Release the specified PQC SIG context.

  @param  context                      Pointer to the PQC SIG context.
**/
void
pqc_sig_free (
  IN   void         *context
  )
{
  pqc_oqs_sig_t         *oqs_sig;

  oqs_sig = context;
  if (oqs_sig->public_key != NULL) {
    free (oqs_sig->public_key);
  }
  if (oqs_sig->secret_key != NULL) {
    zero_mem (oqs_sig->secret_key, oqs_sig->oqs_sig->length_secret_key);
    free (oqs_sig->secret_key);
  }
  OQS_SIG_free (oqs_sig->oqs_sig);
  free (oqs_sig);
}

/**
  Verifies the PQC signature.
a
  @param  context                      Pointer to the PQC SIG context..
  @param  message                      Pointer to octet message to be checked (before hash).
  @param  message_size                  Size of the message in bytes.
  @param  signature                    Pointer to PQC SIG signature to be verified.
  @param  sig_size                      Size of signature in bytes.

  @retval  TRUE   Valid PQC SIG signature.
  @retval  FALSE  Invalid PQC SIG signature or invalid PQC SIG context.
**/
boolean
pqc_sig_verify (
  IN  void         *context,
  IN  const uint8  *message,
  IN  uintn        message_size,
  IN  const uint8  *signature,
  IN  uintn        sig_size
  )
{
  pqc_oqs_sig_t         *oqs_sig;
  OQS_STATUS           status;

  oqs_sig = context;
  status = oqs_sig->oqs_sig->verify (message, message_size, signature, sig_size, oqs_sig->public_key);
  if (status != OQS_SUCCESS) {
    return FALSE;
  }
  return TRUE;
}

/**
  Retrieve the Private Key from the raw data.

  @param  context                      Pointer to the PQC SIG context.
  @param  raw_data                      Pointer to raw data buffer to hold the private key.
  @param  raw_data_size                  Size of the raw data buffer in bytes.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid raw data buffer.
**/
boolean
pqc_sig_set_private_key (
  IN   void         *context,
  IN   const uint8  *raw_data,
  IN   uintn        raw_data_size
  )
{
  pqc_oqs_sig_t         *oqs_sig;

  oqs_sig = context;
  if (raw_data_size != oqs_sig->oqs_sig->length_secret_key) {
    return FALSE;
  }
  if (oqs_sig->secret_key != NULL) {
    zero_mem (oqs_sig->secret_key, oqs_sig->oqs_sig->length_secret_key);
    free (oqs_sig->secret_key);
  }
  oqs_sig->secret_key = malloc (oqs_sig->oqs_sig->length_secret_key);
  if (oqs_sig->secret_key == NULL) {
    return FALSE;
  }
  copy_mem (oqs_sig->secret_key, raw_data, raw_data_size);

  return TRUE;
}

/**
  Retrieve the Private Key from the raw data.

  @param  context                      Pointer to the PQC SIG context.
  @param  raw_data                      Pointer to raw data buffer to hold the private key.
  @param  raw_data_size                  Size of the raw data buffer in bytes.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid raw data buffer.
**/
boolean
pqc_sig_get_private_key (
  IN   void         *context,
  IN   uint8        *raw_data,
  IN   uintn        raw_data_size
  )
{
  pqc_oqs_sig_t         *oqs_sig;

  oqs_sig = context;
  if (raw_data_size != oqs_sig->oqs_sig->length_secret_key) {
    return FALSE;
  }
  if (oqs_sig->secret_key == NULL) {
    return FALSE;
  }
  copy_mem (raw_data, oqs_sig->secret_key, raw_data_size);

  return TRUE;
}

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  @param  context                      Pointer to the PQC SIG context.
  @param  message                      Pointer to octet message to be signed (before hash).
  @param  message_size                  Size of the message in bytes.
  @param  signature                    Pointer to buffer to receive signature.
  @param  sig_size                      On input, the size of Signature buffer in bytes.
                                       On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
boolean
pqc_sig_sign (
  IN      void         *context,
  IN      const uint8  *message,
  IN      uintn        message_size,
  OUT     uint8        *signature,
  IN OUT  uintn        *sig_size
  )
{
  pqc_oqs_sig_t         *oqs_sig;
  OQS_STATUS           status;

  oqs_sig = context;
  status = oqs_sig->oqs_sig->sign (signature, (size_t *)sig_size, message, message_size, oqs_sig->secret_key);
  if (status != OQS_SUCCESS) {
    return FALSE;
  }
  return TRUE;
}

/**
  Allocates and Initializes one PQC KEM context for subsequent use.

  @param  pqc_kem_algo                   pqc_kem_algo

  @return  Pointer to the PQC KEM context that has been initialized.
**/
void *
pqc_kem_new_by_nid (
  IN uintn  nid
  )
{
  pqc_oqs_algo_table_t  *algo_entry;
  pqc_oqs_kem_t         *oqs_kem;

  algo_entry = pqc_get_oqs_kem_algo_entry (nid);
  if (algo_entry == NULL) {
    return NULL;
  }
  if (OQS_KEM_alg_is_enabled (algo_entry->name) == 0) {
    return NULL;
  }
  oqs_kem = malloc (sizeof(pqc_oqs_kem_t));
  if (oqs_kem == NULL) {
    return NULL;
  }
  oqs_kem->oqs_kem = OQS_KEM_new (algo_entry->name);
  if (oqs_kem->oqs_kem == NULL) {
    free (oqs_kem);
    return NULL;
  }
  oqs_kem->secret_key = NULL;
  oqs_kem->public_key = NULL;

  return oqs_kem;
}

/**
  Release the specified PQC KEM context.

  @param  context                      Pointer to the PQC KEM context.
**/
void
pqc_kem_free (
  IN      void         *context
  )
{
  pqc_oqs_kem_t         *oqs_kem;

  oqs_kem = context;
  if (oqs_kem->public_key != NULL) {
    free (oqs_kem->public_key);
  }
  if (oqs_kem->secret_key != NULL) {
    zero_mem (oqs_kem->secret_key, oqs_kem->oqs_kem->length_secret_key);
    free (oqs_kem->secret_key);
  }
  OQS_KEM_free (oqs_kem->oqs_kem);
  free (oqs_kem);
}

/**
  Generate key pairs.

  @param  context                      Pointer to the PQC KEM context.

  @retval  TRUE   Key pairs are generated.
  @retval  FALSE  Fail to generate the key pairs.
**/
boolean
pqc_kem_generate_key (
  IN   void         *context
  )
{
  pqc_oqs_kem_t         *oqs_kem;
  OQS_STATUS           status;

  oqs_kem = context;
  if (oqs_kem->public_key != NULL) {
    free (oqs_kem->public_key);
  }
  oqs_kem->public_key = malloc (oqs_kem->oqs_kem->length_public_key);
  if (oqs_kem->public_key == NULL) {
    return FALSE;
  }
  if (oqs_kem->secret_key != NULL) {
    zero_mem (oqs_kem->secret_key, oqs_kem->oqs_kem->length_secret_key);
    free (oqs_kem->secret_key);
  }
  oqs_kem->secret_key = malloc (oqs_kem->oqs_kem->length_secret_key);
  if (oqs_kem->secret_key == NULL) {
    free (oqs_kem->public_key);
    oqs_kem->public_key = NULL;
    return FALSE;
  }

  status = oqs_kem->oqs_kem->keypair (oqs_kem->public_key, oqs_kem->secret_key);
  if (status != OQS_SUCCESS) {
    free (oqs_kem->public_key);
    oqs_kem->public_key = NULL;
    free (oqs_kem->secret_key);
    oqs_kem->secret_key = NULL;
    return FALSE;
  }

  return TRUE;
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
pqc_kem_get_public_key (
  IN      void         *context,
  OUT     uint8        *public_key,
  IN OUT  uintn        *public_key_size
  )
{
  pqc_oqs_kem_t         *oqs_kem;

  oqs_kem = context;

  if (*public_key_size < oqs_kem->oqs_kem->length_public_key) {
    *public_key_size = oqs_kem->oqs_kem->length_public_key;
    return FALSE;
  }
  *public_key_size = oqs_kem->oqs_kem->length_public_key;

  copy_mem (public_key, oqs_kem->public_key, oqs_kem->oqs_kem->length_public_key);

  return TRUE;
}

boolean
pqc_kem_set_public_key (
  IN      void         *context,
  IN      uint8        *public_key,
  IN      uintn        public_key_size
  )
{
  pqc_oqs_kem_t         *oqs_kem;

  oqs_kem = context;

  if (public_key_size != oqs_kem->oqs_kem->length_public_key) {
    return FALSE;
  }

  if (oqs_kem->public_key != NULL) {
    zero_mem (oqs_kem->public_key, oqs_kem->oqs_kem->length_public_key);
    free (oqs_kem->public_key);
  }
  oqs_kem->public_key = malloc (oqs_kem->oqs_kem->length_public_key);
  if (oqs_kem->public_key == NULL) {
    return FALSE;
  }
  copy_mem (oqs_kem->public_key, public_key, oqs_kem->oqs_kem->length_public_key);

  return TRUE;
}

boolean
pqc_kem_get_private_key (
  IN      void         *context,
  OUT     uint8        *private_key,
  IN OUT  uintn        *private_key_size
  )
{
  pqc_oqs_kem_t         *oqs_kem;

  oqs_kem = context;

  if (*private_key_size < oqs_kem->oqs_kem->length_secret_key) {
    *private_key_size = oqs_kem->oqs_kem->length_secret_key;
    return FALSE;
  }
  *private_key_size = oqs_kem->oqs_kem->length_secret_key;

  copy_mem (private_key, oqs_kem->secret_key, oqs_kem->oqs_kem->length_secret_key);

  return TRUE;
}

boolean
pqc_kem_set_private_key (
  IN      void         *context,
  IN      uint8        *private_key,
  IN      uintn        private_key_size
  )
{
  pqc_oqs_kem_t         *oqs_kem;

  oqs_kem = context;

  if (private_key_size != oqs_kem->oqs_kem->length_secret_key) {
    return FALSE;
  }

  if (oqs_kem->secret_key != NULL) {
    zero_mem (oqs_kem->secret_key, oqs_kem->oqs_kem->length_secret_key);
    free (oqs_kem->secret_key);
  }
  oqs_kem->secret_key = malloc (oqs_kem->oqs_kem->length_secret_key);
  if (oqs_kem->secret_key == NULL) {
    return FALSE;
  }

  copy_mem (oqs_kem->secret_key, private_key, oqs_kem->oqs_kem->length_secret_key);

  return TRUE;
}

/**
  Generate shared key and return the encap data for the shared key with peer public key.

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
  @retval FALSE  shared_key_size or cipher_text_size is not large enough.
**/
boolean
pqc_kem_encap (
  IN OUT  void         *context,
  IN      const uint8  *peer_public_key,
  IN      uintn        peer_public_key_size,
  OUT     uint8        *shared_key,
  IN OUT  uintn        *shared_key_size,
  OUT     uint8        *cipher_text,
  IN OUT  uintn        *cipher_text_size
  )
{
  pqc_oqs_kem_t         *oqs_kem;
  OQS_STATUS           status;

  oqs_kem = context;

  if (peer_public_key_size != oqs_kem->oqs_kem->length_public_key) {
    return FALSE;
  }
  if (*shared_key_size < oqs_kem->oqs_kem->length_shared_secret) {
    *shared_key_size = oqs_kem->oqs_kem->length_shared_secret;
    return FALSE;
  }
  *shared_key_size = oqs_kem->oqs_kem->length_shared_secret;

  if (*cipher_text_size < oqs_kem->oqs_kem->length_ciphertext) {
    *cipher_text_size = oqs_kem->oqs_kem->length_ciphertext;
    return FALSE;
  }
  *cipher_text_size = oqs_kem->oqs_kem->length_ciphertext;

  status = oqs_kem->oqs_kem->encaps (cipher_text, shared_key, peer_public_key);
  if (status != OQS_SUCCESS) {
    return FALSE;
  }

  return TRUE;
}

/**
  Decap the cipher text to shared key with private key.

  @param  context                      Pointer to the PQC KEM context.
  @param  shared_key                    Pointer to the buffer to receive shared key.
  @param  shared_key_size                On input, the size of shared Key buffer in bytes.
                                       On output, the size of data returned in shared Key buffer in bytes.
  @param  cipher_text                   Pointer to the buffer to encapsulated cipher text for the shared key.
  @param  cipher_text_size               The size of cipher text buffer in bytes.

  @retval TRUE   PQC KEM shared key is decapsulated succeeded.
  @retval FALSE  PQC KEM shared key decapsulation failed.
  @retval FALSE  shared_key_size is not large enough.
**/
boolean
pqc_kem_decap (
  IN OUT  void         *context,
  OUT     uint8        *shared_key,
  IN OUT  uintn        *shared_key_size,
  IN      uint8        *cipher_text,
  IN      uintn        cipher_text_size
  )
{
  pqc_oqs_kem_t         *oqs_kem;
  OQS_STATUS           status;

  oqs_kem = context;

  if (cipher_text_size != oqs_kem->oqs_kem->length_ciphertext) {
    return FALSE;
  }
  if (*shared_key_size < oqs_kem->oqs_kem->length_shared_secret) {
    *shared_key_size = oqs_kem->oqs_kem->length_shared_secret;
    return FALSE;
  }
  *shared_key_size = oqs_kem->oqs_kem->length_shared_secret;

  status = oqs_kem->oqs_kem->decaps (shared_key, cipher_text, oqs_kem->secret_key);
  if (status != OQS_SUCCESS) {
    return FALSE;
  }
  return TRUE;
}

