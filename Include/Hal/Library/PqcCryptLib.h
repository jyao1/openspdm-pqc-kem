/** @file
  SPDM PQC Crypto library.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __PQC_CRYPTO_LIB_H__
#define __PQC_CRYPTO_LIB_H__

#include <Base.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>

// 0x00AABBCC
// AA = 0, reserved to modern crypto.
// AA = 1, PQC_SIG
// AA = 2, PQC_KEM
// BB = 0, reserved for NIST default one.

// DILITHIUM
#define PQC_CRYPTO_SIG_NID_DILITHIUM                    0x10100
#define PQC_CRYPTO_SIG_NID_DILITHIUM_2                  (PQC_CRYPTO_SIG_NID_DILITHIUM + 0)
#define PQC_CRYPTO_SIG_NID_DILITHIUM_3                  (PQC_CRYPTO_SIG_NID_DILITHIUM + 1)
#define PQC_CRYPTO_SIG_NID_DILITHIUM_5                  (PQC_CRYPTO_SIG_NID_DILITHIUM + 2)
#define PQC_CRYPTO_SIG_NID_DILITHIUM_2_AES              (PQC_CRYPTO_SIG_NID_DILITHIUM + 3)
#define PQC_CRYPTO_SIG_NID_DILITHIUM_3_AES              (PQC_CRYPTO_SIG_NID_DILITHIUM + 4)
#define PQC_CRYPTO_SIG_NID_DILITHIUM_5_AES              (PQC_CRYPTO_SIG_NID_DILITHIUM + 5)

// FALCON
#define PQC_CRYPTO_SIG_NID_FALCON                       0x10200
#define PQC_CRYPTO_SIG_NID_FALCON_512                   (PQC_CRYPTO_SIG_NID_FALCON + 0)
#define PQC_CRYPTO_SIG_NID_FALCON_1024                  (PQC_CRYPTO_SIG_NID_FALCON + 1)

// RAINBOW
#define PQC_CRYPTO_SIG_NID_RAINBOW                      0x10300
#define PQC_CRYPTO_SIG_NID_RAINBOW_I_CLASSIC            (PQC_CRYPTO_SIG_NID_RAINBOW + 0)
#define PQC_CRYPTO_SIG_NID_RAINBOW_I_CIRCUMZENITHAL     (PQC_CRYPTO_SIG_NID_RAINBOW + 1)
#define PQC_CRYPTO_SIG_NID_RAINBOW_I_COMPRESSED         (PQC_CRYPTO_SIG_NID_RAINBOW + 2)
#define PQC_CRYPTO_SIG_NID_RAINBOW_III_CLASSIC          (PQC_CRYPTO_SIG_NID_RAINBOW + 3)
#define PQC_CRYPTO_SIG_NID_RAINBOW_III_CIRCUMZENITHAL   (PQC_CRYPTO_SIG_NID_RAINBOW + 4)
#define PQC_CRYPTO_SIG_NID_RAINBOW_III_COMPRESSED       (PQC_CRYPTO_SIG_NID_RAINBOW + 5)
#define PQC_CRYPTO_SIG_NID_RAINBOW_V_CLASSIC            (PQC_CRYPTO_SIG_NID_RAINBOW + 6)
#define PQC_CRYPTO_SIG_NID_RAINBOW_V_CIRCUMZENITHAL     (PQC_CRYPTO_SIG_NID_RAINBOW + 7)
#define PQC_CRYPTO_SIG_NID_RAINBOW_V_COMPRESSED         (PQC_CRYPTO_SIG_NID_RAINBOW + 8)

// SPHINCS
#define PQC_CRYPTO_SIG_NID_SPHINCS                      0x10400
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 0)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 1)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 2)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 3)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 4)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 5)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 6)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 7)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 8)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 9)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 10)
#define PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 11)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 12)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 13)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 14)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 15)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 16)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 17)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 18)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 19)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 20)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 21)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_ROBUST   (PQC_CRYPTO_SIG_NID_SPHINCS + 22)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_SIMPLE   (PQC_CRYPTO_SIG_NID_SPHINCS + 23)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_ROBUST (PQC_CRYPTO_SIG_NID_SPHINCS + 24)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_SIMPLE (PQC_CRYPTO_SIG_NID_SPHINCS + 25)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_ROBUST (PQC_CRYPTO_SIG_NID_SPHINCS + 26)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_SIMPLE (PQC_CRYPTO_SIG_NID_SPHINCS + 27)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_ROBUST (PQC_CRYPTO_SIG_NID_SPHINCS + 28)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_SIMPLE (PQC_CRYPTO_SIG_NID_SPHINCS + 29)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_ROBUST (PQC_CRYPTO_SIG_NID_SPHINCS + 30)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_SIMPLE (PQC_CRYPTO_SIG_NID_SPHINCS + 31)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_ROBUST (PQC_CRYPTO_SIG_NID_SPHINCS + 32)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_SIMPLE (PQC_CRYPTO_SIG_NID_SPHINCS + 33)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_ROBUST (PQC_CRYPTO_SIG_NID_SPHINCS + 34)
#define PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_SIMPLE (PQC_CRYPTO_SIG_NID_SPHINCS + 35)

// PICNIC
#define PQC_CRYPTO_SIG_NID_PICNIC                       0x10500
#define PQC_CRYPTO_SIG_NID_PICNIC_L1_FS                 (PQC_CRYPTO_SIG_NID_PICNIC + 0)
#define PQC_CRYPTO_SIG_NID_PICNIC_L1_UR                 (PQC_CRYPTO_SIG_NID_PICNIC + 1)
#define PQC_CRYPTO_SIG_NID_PICNIC_L1_FULL               (PQC_CRYPTO_SIG_NID_PICNIC + 2)
#define PQC_CRYPTO_SIG_NID_PICNIC_L3_FS                 (PQC_CRYPTO_SIG_NID_PICNIC + 3)
#define PQC_CRYPTO_SIG_NID_PICNIC_L3_UR                 (PQC_CRYPTO_SIG_NID_PICNIC + 4)
#define PQC_CRYPTO_SIG_NID_PICNIC_L3_FULL               (PQC_CRYPTO_SIG_NID_PICNIC + 5)
#define PQC_CRYPTO_SIG_NID_PICNIC_L5_FS                 (PQC_CRYPTO_SIG_NID_PICNIC + 6)
#define PQC_CRYPTO_SIG_NID_PICNIC_L5_UR                 (PQC_CRYPTO_SIG_NID_PICNIC + 7)
#define PQC_CRYPTO_SIG_NID_PICNIC_L5_FULL               (PQC_CRYPTO_SIG_NID_PICNIC + 8)
#define PQC_CRYPTO_SIG_NID_PICNIC3_L1                   (PQC_CRYPTO_SIG_NID_PICNIC + 9)
#define PQC_CRYPTO_SIG_NID_PICNIC3_L3                   (PQC_CRYPTO_SIG_NID_PICNIC + 10)
#define PQC_CRYPTO_SIG_NID_PICNIC3_L5                   (PQC_CRYPTO_SIG_NID_PICNIC + 11)

// BIKE
#define PQC_CRYPTO_KEM_NID_BIKE                          0x20100
#define PQC_CRYPTO_KEM_NID_BIKE1_L1_CPA                  (PQC_CRYPTO_KEM_NID_BIKE + 0)
#define PQC_CRYPTO_KEM_NID_BIKE1_L3_CPA                  (PQC_CRYPTO_KEM_NID_BIKE + 1)
#define PQC_CRYPTO_KEM_NID_BIKE1_L1_FO                   (PQC_CRYPTO_KEM_NID_BIKE + 2)
#define PQC_CRYPTO_KEM_NID_BIKE1_L3_FO                   (PQC_CRYPTO_KEM_NID_BIKE + 3)

// CLASSIC_MCELIECE
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE              0x20200
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864       (PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE + 0)
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864F      (PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE + 1)
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896       (PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE + 2)
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896F      (PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE + 3)
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128      (PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE + 4)
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128F     (PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE + 5)
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119      (PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE + 6)
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119F     (PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE + 7)
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128      (PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE + 8)
#define PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128F     (PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE + 9)

// HQC
#define PQC_CRYPTO_KEM_NID_HQC                           0x20300
#define PQC_CRYPTO_KEM_NID_HQC_128                       (PQC_CRYPTO_KEM_NID_HQC + 0)
#define PQC_CRYPTO_KEM_NID_HQC_192                       (PQC_CRYPTO_KEM_NID_HQC + 1)
#define PQC_CRYPTO_KEM_NID_HQC_256                       (PQC_CRYPTO_KEM_NID_HQC + 2)

// KYBER
#define PQC_CRYPTO_KEM_NID_KYBER                         0x20400
#define PQC_CRYPTO_KEM_NID_KYBER_512                     (PQC_CRYPTO_KEM_NID_KYBER + 0)
#define PQC_CRYPTO_KEM_NID_KYBER_768                     (PQC_CRYPTO_KEM_NID_KYBER + 1)
#define PQC_CRYPTO_KEM_NID_KYBER_1024                    (PQC_CRYPTO_KEM_NID_KYBER + 2)
#define PQC_CRYPTO_KEM_NID_KYBER_512_90S                 (PQC_CRYPTO_KEM_NID_KYBER + 3)
#define PQC_CRYPTO_KEM_NID_KYBER_768_90S                 (PQC_CRYPTO_KEM_NID_KYBER + 4)
#define PQC_CRYPTO_KEM_NID_KYBER_1024_90S                (PQC_CRYPTO_KEM_NID_KYBER + 5)

// NTRU
#define PQC_CRYPTO_KEM_NID_NTRU                          0x20500
#define PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_509             (PQC_CRYPTO_KEM_NID_NTRU + 0)
#define PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_677             (PQC_CRYPTO_KEM_NID_NTRU + 1)
#define PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_821             (PQC_CRYPTO_KEM_NID_NTRU + 2)
#define PQC_CRYPTO_KEM_NID_NTRU_HRSS_701                 (PQC_CRYPTO_KEM_NID_NTRU + 3)

// NTRUPRIME
#define PQC_CRYPTO_KEM_NID_NTRUPRIME                      0x20600
#define PQC_CRYPTO_KEM_NID_NTRULPR653                     (PQC_CRYPTO_KEM_NID_NTRUPRIME + 0)
#define PQC_CRYPTO_KEM_NID_NTRULPR761                     (PQC_CRYPTO_KEM_NID_NTRUPRIME + 1)
#define PQC_CRYPTO_KEM_NID_NTRULPR857                     (PQC_CRYPTO_KEM_NID_NTRUPRIME + 2)
#define PQC_CRYPTO_KEM_NID_SNTRUP653                      (PQC_CRYPTO_KEM_NID_NTRUPRIME + 3)
#define PQC_CRYPTO_KEM_NID_SNTRUP761                      (PQC_CRYPTO_KEM_NID_NTRUPRIME + 4)
#define PQC_CRYPTO_KEM_NID_SNTRUP857                      (PQC_CRYPTO_KEM_NID_NTRUPRIME + 5)

// SABER
#define PQC_CRYPTO_KEM_NID_SABER                          0x20700
#define PQC_CRYPTO_KEM_NID_LIGHTSABER_KEM                 (PQC_CRYPTO_KEM_NID_SABER + 0)
#define PQC_CRYPTO_KEM_NID_SABER_KEM                      (PQC_CRYPTO_KEM_NID_SABER + 1)
#define PQC_CRYPTO_KEM_NID_FIRESABER_KEM                  (PQC_CRYPTO_KEM_NID_SABER + 2)

// FRODOKEM
#define PQC_CRYPTO_KEM_NID_FRODOKEM                       0x20800
#define PQC_CRYPTO_KEM_NID_FRODOKEM_640_AES               (PQC_CRYPTO_KEM_NID_FRODOKEM + 0)
#define PQC_CRYPTO_KEM_NID_FRODOKEM_640_SHAKE             (PQC_CRYPTO_KEM_NID_FRODOKEM + 1)
#define PQC_CRYPTO_KEM_NID_FRODOKEM_976_AES               (PQC_CRYPTO_KEM_NID_FRODOKEM + 2)
#define PQC_CRYPTO_KEM_NID_FRODOKEM_976_SHAKE             (PQC_CRYPTO_KEM_NID_FRODOKEM + 3)
#define PQC_CRYPTO_KEM_NID_FRODOKEM_1344_AES              (PQC_CRYPTO_KEM_NID_FRODOKEM + 4)
#define PQC_CRYPTO_KEM_NID_FRODOKEM_1344_SHAKE            (PQC_CRYPTO_KEM_NID_FRODOKEM + 5)

// SIKE
#define PQC_CRYPTO_KEM_NID_SIKE                           0x20900
#define PQC_CRYPTO_KEM_NID_SIDH_P434                      (PQC_CRYPTO_KEM_NID_SIKE + 0)
#define PQC_CRYPTO_KEM_NID_SIDH_P434_COMPRESSED           (PQC_CRYPTO_KEM_NID_SIKE + 1)
#define PQC_CRYPTO_KEM_NID_SIDH_P503                      (PQC_CRYPTO_KEM_NID_SIKE + 2)
#define PQC_CRYPTO_KEM_NID_SIDH_P503_COMPRESSED           (PQC_CRYPTO_KEM_NID_SIKE + 3)
#define PQC_CRYPTO_KEM_NID_SIDH_P610                      (PQC_CRYPTO_KEM_NID_SIKE + 4)
#define PQC_CRYPTO_KEM_NID_SIDH_P610_COMPRESSED           (PQC_CRYPTO_KEM_NID_SIKE + 5)
#define PQC_CRYPTO_KEM_NID_SIDH_P751                      (PQC_CRYPTO_KEM_NID_SIKE + 6)
#define PQC_CRYPTO_KEM_NID_SIDH_P751_COMPRESSED           (PQC_CRYPTO_KEM_NID_SIKE + 7)
#define PQC_CRYPTO_KEM_NID_SIKE_P434                      (PQC_CRYPTO_KEM_NID_SIKE + 8)
#define PQC_CRYPTO_KEM_NID_SIKE_P434_COMPRESSED           (PQC_CRYPTO_KEM_NID_SIKE + 9)
#define PQC_CRYPTO_KEM_NID_SIKE_P503                      (PQC_CRYPTO_KEM_NID_SIKE + 10)
#define PQC_CRYPTO_KEM_NID_SIKE_P503_COMPRESSED           (PQC_CRYPTO_KEM_NID_SIKE + 11)
#define PQC_CRYPTO_KEM_NID_SIKE_P610                      (PQC_CRYPTO_KEM_NID_SIKE + 12)
#define PQC_CRYPTO_KEM_NID_SIKE_P610_COMPRESSED           (PQC_CRYPTO_KEM_NID_SIKE + 13)
#define PQC_CRYPTO_KEM_NID_SIKE_P751                      (PQC_CRYPTO_KEM_NID_SIKE + 14)
#define PQC_CRYPTO_KEM_NID_SIKE_P751_COMPRESSED           (PQC_CRYPTO_KEM_NID_SIKE + 15)

/**
  This function returns the PQC SIG algorithm size.

  @param Nid cipher NID

  @return PQC SIG algorithm size.
**/
UINTN
EFIAPI
PqcGetOqsSigSignatureSize (
  IN UINTN  Nid
  );

/**
  This function returns the PQC SIG algorithm size.

  @param Nid cipher NID

  @return PQC SIG algorithm size.
**/
UINTN
EFIAPI
PqcGetOqsSigPrivKeySize (
  IN UINTN  Nid
  );

/**
  This function returns the PQC SIG algorithm size.

  @param Nid cipher NID

  @return PQC SIG algorithm size.
**/
UINTN
EFIAPI
PqcGetOqsSigPubKeySize (
  IN UINTN  Nid
  );

/**
  This function returns the PQC KEM algorithm key size.

  @param Nid cipher NID

  @return PQC KEM algorithm key size.
**/
UINTN
EFIAPI
PqcGetOqsKemSharedKeySize (
  IN UINTN  Nid
  );

/**
  This function returns the PQC KEM algorithm key size.

  @param Nid cipher NID

  @return PQC KEM algorithm key size.
**/
UINTN
EFIAPI
PqcGetOqsKemCipherTextSize (
  IN UINTN  Nid
  );

/**
  This function returns the PQC KEM algorithm key size.

  @param Nid cipher NID

  @return PQC KEM algorithm key size.
**/
UINTN
EFIAPI
PqcGetOqsKemPrivKeySize (
  IN UINTN  Nid
  );

/**
  This function returns the PQC KEM algorithm key size.

  @param Nid cipher NID

  @return PQC KEM algorithm key size.
**/
UINTN
EFIAPI
PqcGetOqsKemPubKeySize (
  IN UINTN  Nid
  );

/**
  Allocates and Initializes one PQC SIG Context for subsequent use.

  @param Nid cipher NID

  @return  Pointer to the PQC SIG Context that has been initialized.
**/
VOID *
EFIAPI
PqcSigNewByNid (
  IN UINTN  Nid
  );

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
  );

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
  );

/**
  Release the specified PQC SIG context.

  @param  Context                      Pointer to the PQC SIG context.
**/
VOID
EFIAPI
PqcSigFree (
  IN  VOID         *Context
  );

/**
  Verifies the PQC signature.

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
  );

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
  );

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
  );

/**
  Allocates and Initializes one PQC KEM Context for subsequent use.

  @param Nid cipher NID

  @return  Pointer to the PQC KEM Context that has been initialized.
**/
VOID *
EFIAPI
PqcKemNewByNid (
  IN UINTN  Nid
  );

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
  );

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
  );

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
  );

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
  );

/**
  Release the specified PQC KEM context.

  @param  Context                      Pointer to the PQC KEM context.
**/
VOID
EFIAPI
PqcKemFree (
  IN  VOID  *Context
  );

#endif