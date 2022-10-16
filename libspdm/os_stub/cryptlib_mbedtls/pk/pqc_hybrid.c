/** @file
  Elliptic Curve Wrapper Implementation over OpenSSL.

  RFC 8422 - Elliptic Curve Cryptography (ECC) Cipher Suites
  FIPS 186-4 - Digital signature Standard (DSS)

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "internal_crypt_lib.h"
/**
  Release the specified PQC context.
  
  @param[in]  pqc_hybrid_context  Pointer to the PQC context to be released.

**/
void
pqc_hybrid_free (
  IN  void  *pqc_hybrid_context
  )
{
}

/**
  Carries out the PQC signature.

  @param[in]       pqc_hybrid_context    Pointer to PQC context for signature generation.
  @param[in]       hash_nid      hash NID
  @param[in]       message       Pointer to octet message hash to be signed.
  @param[in]       size          size of the message hash in bytes.
  @param[out]      signature    Pointer to buffer to receive PQC signature.
  @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
                                On output, the size of data returned in signature buffer in bytes.

  @retval  TRUE   signature successfully generated.
  @retval  FALSE  signature generation failed.
  @retval  FALSE  sig_size is too small.

**/
boolean
pqc_hybrid_sign (
  IN      void         *pqc_hybrid_context,
  IN      uintn        hash_nid,
  IN      const uint8  *message,
  IN      uintn        size,
  OUT     uint8        *signature,
  IN OUT  uintn        *sig_size
  )
{
  return FALSE;
}

/**
  Verifies the PQC signature.

  @param[in]  pqc_hybrid_context    Pointer to PQC context for signature verification.
  @param[in]  hash_nid      hash NID
  @param[in]  message       Pointer to octet message hash to be checked.
  @param[in]  size          size of the message hash in bytes.
  @param[in]  signature    Pointer to PQC signature to be verified.
  @param[in]  sig_size      size of signature in bytes.

  @retval  TRUE   Valid signature encoded.
  @retval  FALSE  Invalid signature or invalid PQC context.

**/
boolean
pqc_hybrid_verify (
  IN  void         *pqc_hybrid_context,
  IN  uintn        hash_nid,
  IN  const uint8  *message,
  IN  uintn        size,
  IN  const uint8  *signature,
  IN  uintn        sig_size
  )
{
  return FALSE;
}
