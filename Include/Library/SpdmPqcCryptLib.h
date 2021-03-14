/** @file
  SPDM PQC Crypto library.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_PQC_CRYPTO_LIB_H__
#define __SPDM_PQC_CRYPTO_LIB_H__

#include "SpdmLibConfig.h"

#include <Base.h>
#include <IndustryStandard/SpdmPqc.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/SpdmCryptLib.h>

#define MAX_PQC_KEM_KEY_SIZE   0 // TBD
#define MAX_PQC_SIG_KEY_SIZE   0 // TBD

/**
  This function returns the SPDM PqcSigAlgo algorithm size.

  @param  PqcSigAlgo                   SPDM PqcSigAlgo

  @return SPDM PqcSigAlgo algorithm size.
**/
UINT32
EFIAPI
GetSpdmPqcSigSignatureSize (
  IN   PQC_ALGO     PqcSigAlgo
  );

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
  );

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
  );

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
  );

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
  );

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
  );

/**
  This function returns the SPDM requester PQC SIG algorithm size.

  @param  ReqPqcSigAlgo                SPDM ReqPqcSigAlgo

  @return SPDM requester PQC SIG algorithm size.
**/
UINT32
EFIAPI
GetSpdmReqPqcSigSignatureSize (
  IN   PQC_ALGO     ReqPqcSigAlgo
  );

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
  );

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
  );

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
  );

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
SpdmReqPqcSigGetPrivateKeyFromPem (
  IN   PQC_ALGO     ReqPqcSigAlgo,
  IN   CONST UINT8  *RawData,
  IN   UINTN        RawDataSize,
  OUT  VOID         **Context
  );

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
  );

/**
  This function returns the SPDM PQC KEM algorithm key size.

  @param  PqcKemAlgo                   SPDM PqcKemAlgo

  @return SPDM PQC KEM algorithm key size.
**/
UINT32
EFIAPI
GetSpdmPqcKemPubKeySize (
  IN      PQC_ALGO     PqcKemAlgo
  );

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
  );

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
  );

/**
  Generates PQC KEM public key,
  based upon negotiated PQC KEM algorithm.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter PublicKey and PublicKeySize. PQC KEM context is updated accordingly.
  If the PublicKey buffer is too small to hold the public key, FALSE is returned and
  PublicKeySize is set to the required buffer size to obtain the public key.

  @param  PqcKemAlgo                   SPDM PqcKemAlgo
  @param  Context                      Pointer to the PQC KEM context.
  @param  PublicKey                    Pointer to the buffer to receive generated public key.
  @param  PublicKeySize                On input, the size of PublicKey buffer in bytes.
                                       On output, the size of data returned in PublicKey buffer in bytes.

  @retval TRUE   PQC KEM public key generation succeeded.
  @retval FALSE  PQC KEM public key generation failed.
  @retval FALSE  PublicKeySize is not large enough.
**/
BOOLEAN
EFIAPI
SpdmPqcKemGenerateKey (
  IN      PQC_ALGO     PqcKemAlgo,
  IN OUT  VOID         *Context,
  OUT     UINT8        *PublicKey,
  IN OUT  UINTN        *PublicKeySize
  );

/**
  Computes exchanged common key,
  based upon negotiated PQC KEM algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  PqcKemAlgo                   SPDM PqcKemAlgo
  @param  Context                      Pointer to the PQC KEM context.
  @param  PeerPublicKey                Pointer to the peer's public key.
  @param  PeerPublicKeySize            Size of peer's public key in bytes.
  @param  Key                          Pointer to the buffer to receive generated key.
  @param  KeySize                      On input, the size of Key buffer in bytes.
                                       On output, the size of data returned in Key buffer in bytes.

  @retval TRUE   PQC KEM exchanged key generation succeeded.
  @retval FALSE  PQC KEM exchanged key generation failed.
  @retval FALSE  KeySize is not large enough.
**/
BOOLEAN
EFIAPI
SpdmPqcKemComputeKey (
  IN      PQC_ALGO     PqcKemAlgo,
  IN OUT  VOID         *Context,
  IN      CONST UINT8  *PeerPublic,
  IN      UINTN        PeerPublicSize,
  OUT     UINT8        *Key,
  IN OUT  UINTN        *KeySize
  );

#endif