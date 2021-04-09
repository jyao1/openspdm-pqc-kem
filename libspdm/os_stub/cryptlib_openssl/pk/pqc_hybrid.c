/** @file
  Elliptic Curve Wrapper Implementation over OpenSSL.

  RFC 8422 - Elliptic Curve Cryptography (ECC) Cipher Suites
  FIPS 186-4 - Digital signature Standard (DSS)

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "internal_crypt_lib.h"
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

static
uint32
ntohl (
  uint32 a
  )
{
  uint32 b;
  b = ((a & 0xFF) << 24) |
      ((a & 0xFF00) << 8) |
      ((a & 0xFF0000) >> 8) |
      ((a & 0xFF000000) >> 24);
  return b;
}

static
uint32
htonl (
  uint32 a
  )
{
  return ntohl (a);
}

#define MAX_PQC_SIG_SIGNATURE_SIZE     49216   // MAX_PQC_SIG_SIGNATURE_SIZE_SPHINCS - need align with definition in spdm_pqc_crypt_lib
#define MAX_CLASSIC_SIG_SIGNATURE_SIZE 384     // RSA3072
#define MAC_HYBRID_SIG_SIGNATURE_SIZE  (4 + MAX_CLASSIC_SIG_SIGNATURE_SIZE + MAX_PQC_SIG_SIGNATURE_SIZE)

/*
NOTE:

openssl PQC Hybrid sign uses below format:
    Signature = 4 bytes Classic Signature Size (big endian) || Classic Signature || PqcSig Signature
where the classic signature uses below format:
    RSA3072: 384 bytes raw binary
    P256:    72  bytes DER (max) {30, 46, 02, 21, {00 ...}, 02, 21, {00 ...}}, {30, 44, 02, 20, {00 ...}, 02, 20, {00 ...}}
    P384:    104 bytes DER (max) {30, 66, 02, 31, {00 ...}, 02, 31, {00 ...}}, {30, 64, 02, 30, {00 ...}, 02, 30, {00 ...}}
    P521:    141 bytes DER (max) {30, 81, 8A, 02, 43, {00 ...}, 02, 43, {00 ...}}, {30, 81, 88, 02, 42, {00 ...}, 02, 42, {00 ...}}
if classic signature is absent, the 4 bytes size is absent.

The expected PQC sign uses below format:
    Signature = BaseAsym Signature || 4 bytes PqcSig Signature Size || PqcSig Signature
where the classic signature uses below format:
    RSA3072: 384 bytes raw binary
    P256:    64  bytes raw binary {32 bytes r + 32 bytes s}
    P384:    96  bytes raw binary {48 bytes r + 48 bytes s}
    P521:    132 bytes raw binary {66 bytes r + 66 bytes s}
*/

typedef enum {
  pqc_classic_type_none,
  pqc_classic_type_rsa3072,
  pqc_classic_type_p256,
  pqc_classic_type_p384,
  pqc_classic_type_p521,
} pqc_classic_type_t;

int m_pqc_hybrid_pkey_type[] = {
  EVP_PKEY_DILITHIUM2,
  EVP_PKEY_P256_DILITHIUM2,
  EVP_PKEY_RSA3072_DILITHIUM2,
  EVP_PKEY_DILITHIUM3,
  EVP_PKEY_P384_DILITHIUM3,
  EVP_PKEY_DILITHIUM5,
  EVP_PKEY_P521_DILITHIUM5,
  EVP_PKEY_DILITHIUM2_AES,
  EVP_PKEY_P256_DILITHIUM2_AES,
  EVP_PKEY_RSA3072_DILITHIUM2_AES,
  EVP_PKEY_DILITHIUM3_AES,
  EVP_PKEY_P384_DILITHIUM3_AES,
  EVP_PKEY_DILITHIUM5_AES,
  EVP_PKEY_P521_DILITHIUM5_AES,

  EVP_PKEY_FALCON512,
  EVP_PKEY_P256_FALCON512,
  EVP_PKEY_RSA3072_FALCON512,
  EVP_PKEY_FALCON1024,
  EVP_PKEY_P521_FALCON1024,

  EVP_PKEY_PICNICL1FULL,
  EVP_PKEY_P256_PICNICL1FULL,
  EVP_PKEY_RSA3072_PICNICL1FULL,
  EVP_PKEY_PICNIC3L1,
  EVP_PKEY_P256_PICNIC3L1,
  EVP_PKEY_RSA3072_PICNIC3L1,

  EVP_PKEY_RAINBOWICLASSIC,
  EVP_PKEY_P256_RAINBOWICLASSIC,
  EVP_PKEY_RSA3072_RAINBOWICLASSIC,
  EVP_PKEY_RAINBOWVCLASSIC,
  EVP_PKEY_P521_RAINBOWVCLASSIC,

  EVP_PKEY_SPHINCSHARAKA128FROBUST,
  EVP_PKEY_P256_SPHINCSHARAKA128FROBUST,
  EVP_PKEY_RSA3072_SPHINCSHARAKA128FROBUST,
  EVP_PKEY_SPHINCSSHA256128FROBUST,
  EVP_PKEY_P256_SPHINCSSHA256128FROBUST,
  EVP_PKEY_RSA3072_SPHINCSSHA256128FROBUST,
  EVP_PKEY_SPHINCSSHAKE256128FROBUST,
  EVP_PKEY_P256_SPHINCSSHAKE256128FROBUST,
  EVP_PKEY_RSA3072_SPHINCSSHAKE256128FROBUST,
};

boolean
is_pqc_hybrid_pkey_type (
  IN int pkey_type
  )
{
  uintn  index;
  for (index = 0; index < ARRAY_SIZE(m_pqc_hybrid_pkey_type); index++) {
    if (pkey_type == m_pqc_hybrid_pkey_type[index]) {
      return TRUE;
    }
  }
  return FALSE;
}

pqc_classic_type_t
get_pqc_classic_type (
  IN int pkey_type
  )
{
  switch (pkey_type) {
  case EVP_PKEY_DILITHIUM2:
  case EVP_PKEY_DILITHIUM3:
  case EVP_PKEY_DILITHIUM5:
  case EVP_PKEY_DILITHIUM2_AES:
  case EVP_PKEY_DILITHIUM3_AES:
  case EVP_PKEY_DILITHIUM5_AES:
  case EVP_PKEY_FALCON512:
  case EVP_PKEY_FALCON1024:
  case EVP_PKEY_PICNICL1FULL:
  case EVP_PKEY_PICNIC3L1:
  case EVP_PKEY_RAINBOWICLASSIC:
  case EVP_PKEY_RAINBOWVCLASSIC:
  case EVP_PKEY_SPHINCSHARAKA128FROBUST:
  case EVP_PKEY_SPHINCSSHA256128FROBUST:
  case EVP_PKEY_SPHINCSSHAKE256128FROBUST:
    return pqc_classic_type_none;

  case EVP_PKEY_P256_DILITHIUM2:
  case EVP_PKEY_P256_DILITHIUM2_AES:
  case EVP_PKEY_P256_FALCON512:
  case EVP_PKEY_P256_PICNICL1FULL:
  case EVP_PKEY_P256_PICNIC3L1:
  case EVP_PKEY_P256_RAINBOWICLASSIC:
  case EVP_PKEY_P256_SPHINCSHARAKA128FROBUST:
  case EVP_PKEY_P256_SPHINCSSHA256128FROBUST:
  case EVP_PKEY_P256_SPHINCSSHAKE256128FROBUST:
    return pqc_classic_type_p256;

  case EVP_PKEY_RSA3072_DILITHIUM2:
  case EVP_PKEY_RSA3072_DILITHIUM2_AES:
  case EVP_PKEY_RSA3072_FALCON512:
  case EVP_PKEY_RSA3072_PICNICL1FULL:
  case EVP_PKEY_RSA3072_PICNIC3L1:
  case EVP_PKEY_RSA3072_RAINBOWICLASSIC:
  case EVP_PKEY_RSA3072_SPHINCSHARAKA128FROBUST:
  case EVP_PKEY_RSA3072_SPHINCSSHA256128FROBUST:
  case EVP_PKEY_RSA3072_SPHINCSSHAKE256128FROBUST:
    return pqc_classic_type_rsa3072;

  case EVP_PKEY_P384_DILITHIUM3:
  case EVP_PKEY_P384_DILITHIUM3_AES:
    return pqc_classic_type_p384;

  case EVP_PKEY_P521_DILITHIUM5:
  case EVP_PKEY_P521_DILITHIUM5_AES:
  case EVP_PKEY_P521_FALCON1024:
  case EVP_PKEY_P521_RAINBOWVCLASSIC:
    return pqc_classic_type_p521;
  
  default:
    ASSERT (FALSE);
    return 0;
  }
}

/**
  Release the specified PQC context.
  
  @param[in]  pqc_hybrid_context  Pointer to the PQC context to be released.

**/
void
pqc_hybrid_free (
  IN  void  *pqc_hybrid_context
  )
{
  EVP_PKEY_free ((EVP_PKEY *) pqc_hybrid_context);
}

void
ecc_signature_der_to_bin (
  IN      uint8        *der_signature,
  IN      uintn        der_sig_size,
  OUT     uint8        *signature,
  IN      uintn        sig_size
  );

void
openssl_signature_to_pqc_bin (
  IN      pqc_classic_type_t classic_type,
  IN      uint8        *openssl_signature,
  IN      uintn        openssl_sig_size,
  OUT     uint8        *signature,
  IN      uintn        sig_size
  )
{
  uint32  openssl_classic_sig_size;
  uint32  pqc_sig_size;
  uint8   *openssl_pqc_signature;

  if (classic_type != pqc_classic_type_none) {
    openssl_classic_sig_size = *(uint32 *)openssl_signature;
    openssl_classic_sig_size = ntohl (openssl_classic_sig_size);
    pqc_sig_size = (uint32)(openssl_sig_size - sizeof(uint32) - openssl_classic_sig_size);
    openssl_pqc_signature = openssl_signature + sizeof(uint32) + openssl_classic_sig_size;
  }

  switch (classic_type) {
  case pqc_classic_type_none:
    ASSERT (sig_size >= openssl_sig_size + sizeof(uint32));
    *(uint32 *)signature = (uint32)openssl_sig_size;
    copy_mem (signature + sizeof(uint32), openssl_signature, openssl_sig_size);
    break;

  case pqc_classic_type_rsa3072:
    ASSERT (openssl_classic_sig_size == 384);
    ASSERT (sig_size >= 384 + sizeof(uint32) + pqc_sig_size);
    copy_mem (signature, openssl_signature + sizeof(uint32), 384);
    copy_mem (signature + 384, &pqc_sig_size, sizeof(uint32));
    copy_mem (signature + 384 + sizeof(uint32), openssl_pqc_signature, pqc_sig_size);
    break;
  case pqc_classic_type_p256:
    ASSERT (openssl_classic_sig_size <= 72);
    ASSERT (sig_size >= 32 * 2 + sizeof(uint32) + pqc_sig_size);
    ecc_signature_der_to_bin (openssl_signature + sizeof(uint32), openssl_classic_sig_size, signature, 32 * 2);
    copy_mem (signature + 32 * 2, &pqc_sig_size, sizeof(uint32));
    copy_mem (signature + 32 * 2 + sizeof(uint32), openssl_pqc_signature, pqc_sig_size);
    break;
  case pqc_classic_type_p384:
    ASSERT (openssl_classic_sig_size <= 104);
    ASSERT (sig_size >= 48 * 2 + sizeof(uint32) + pqc_sig_size);
    ecc_signature_der_to_bin (openssl_signature + sizeof(uint32), openssl_classic_sig_size, signature, 48 * 2);
    copy_mem (signature + 48 * 2, &pqc_sig_size, sizeof(uint32));
    copy_mem (signature + 48 * 2 + sizeof(uint32), openssl_pqc_signature, pqc_sig_size);
    break;
  case pqc_classic_type_p521:
    ASSERT (openssl_classic_sig_size <= 141);
    ASSERT (sig_size >= 66 * 2 + sizeof(uint32) + pqc_sig_size);
    ecc_signature_der_to_bin (openssl_signature + sizeof(uint32), openssl_classic_sig_size, signature, 66 * 2);
    copy_mem (signature + 66 * 2, &pqc_sig_size, sizeof(uint32));
    copy_mem (signature + 66 * 2 + sizeof(uint32), openssl_pqc_signature, pqc_sig_size);
    break;

  default:
    ASSERT (FALSE);
    return ;
  }

  return ;
}

void
ecc_signature_bin_to_der (
  IN      uint8        *signature,
  IN      uintn        sig_size,
  OUT     uint8        *der_signature,
  IN OUT  uintn        *der_sig_size_in_out
  );

void
openssl_signature_from_pqc_bin (
  IN      pqc_classic_type_t classic_type,
  IN      uint8        *signature,
  IN      uintn        sig_size,
  OUT     uint8        *openssl_signature,
  IN OUT  uintn        *openssl_sig_size_in_out
  )
{
  uintn   openssl_classic_sig_size;
  uint32  pqc_sig_size;
  uint8   *pqc_sigature;

  switch (classic_type) {
  case pqc_classic_type_none:
    pqc_sig_size = *(uint32 *)signature;
    pqc_sigature = signature + sizeof(uint32);
    ASSERT (*openssl_sig_size_in_out >= pqc_sig_size);
    copy_mem (openssl_signature, pqc_sigature, pqc_sig_size);
    *openssl_sig_size_in_out = pqc_sig_size;
    break;

  case pqc_classic_type_rsa3072:
    pqc_sig_size = *(uint32 *)(signature + 384);
    pqc_sigature = signature + 384 + sizeof(uint32);
    ASSERT (*openssl_sig_size_in_out >= sizeof(uint32) + 384 + pqc_sig_size);
    *(uint32 *)openssl_signature = htonl(384);
    copy_mem (openssl_signature + sizeof(uint32), signature, 384);
    copy_mem (openssl_signature + sizeof(uint32) + 384, pqc_sigature, pqc_sig_size);
    *openssl_sig_size_in_out = sizeof(uint32) + 384 + pqc_sig_size;
    break;

  case pqc_classic_type_p256:
    pqc_sig_size = *(uint32 *)(signature + 32 * 2);
    pqc_sigature = signature + 32 * 2 + sizeof(uint32);
    openssl_classic_sig_size = 72;
    ASSERT (*openssl_sig_size_in_out >= sizeof(uint32) + openssl_classic_sig_size + pqc_sig_size);
    ecc_signature_bin_to_der (signature, 32 * 2, openssl_signature + sizeof(uint32), &openssl_classic_sig_size);
    *(uint32 *)openssl_signature = htonl((uint32)openssl_classic_sig_size);
    copy_mem (openssl_signature + sizeof(uint32) + openssl_classic_sig_size, pqc_sigature, pqc_sig_size);
    *openssl_sig_size_in_out = sizeof(uint32) + openssl_classic_sig_size + pqc_sig_size;
    break;
  case pqc_classic_type_p384:
    pqc_sig_size = *(uint32 *)(signature + 48 * 2);
    pqc_sigature = signature + 48 * 2 + sizeof(uint32);
    openssl_classic_sig_size = 104;
    ASSERT (*openssl_sig_size_in_out >= sizeof(uint32) + openssl_classic_sig_size + pqc_sig_size);
    ecc_signature_bin_to_der (signature, 48 * 2, openssl_signature + sizeof(uint32), &openssl_classic_sig_size);
    *(uint32 *)openssl_signature = htonl((uint32)openssl_classic_sig_size);
    copy_mem (openssl_signature + sizeof(uint32) + openssl_classic_sig_size, pqc_sigature, pqc_sig_size);
    *openssl_sig_size_in_out = sizeof(uint32) + openssl_classic_sig_size + pqc_sig_size;
    break;
  case pqc_classic_type_p521:
    pqc_sig_size = *(uint32 *)(signature + 66 * 2);
    pqc_sigature = signature + 66 * 2 + sizeof(uint32);
    openssl_classic_sig_size = 141;
    ASSERT (*openssl_sig_size_in_out >= sizeof(uint32) + openssl_classic_sig_size + pqc_sig_size);
    ecc_signature_bin_to_der (signature, 66 * 2, openssl_signature + sizeof(uint32), &openssl_classic_sig_size);
    *(uint32 *)openssl_signature = htonl((uint32)openssl_classic_sig_size);
    copy_mem (openssl_signature + sizeof(uint32) + openssl_classic_sig_size, pqc_sigature, pqc_sig_size);
    *openssl_sig_size_in_out = sizeof(uint32) + openssl_classic_sig_size + pqc_sig_size;
    break;

  default:
    ASSERT (FALSE);
    return ;
  }

  return ;
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
  EVP_MD_CTX *mctx;
  int32      result;
  uint8      openssl_signature[MAC_HYBRID_SIG_SIGNATURE_SIZE];
  uintn      openssl_sig_size;
  uintn      expected_sig_size;
  uint32     openssl_classic_sig_size;
  pqc_classic_type_t classic_type;

  if (pqc_hybrid_context == NULL || message == NULL) {
    return FALSE;
  }

  if (signature == NULL) {
    return FALSE;
  }

  mctx = EVP_MD_CTX_new();
  if (mctx == NULL) {
    return FALSE;
  }
  result = EVP_DigestSignInit (mctx, NULL, NULL, NULL, pqc_hybrid_context);
  if (result <= 0) {
    return FALSE;
  }

  openssl_sig_size = sizeof(openssl_signature);
  result = EVP_DigestSign (mctx, openssl_signature, &openssl_sig_size, message, size);
  if (result <= 0) {
    return FALSE;
  }

  openssl_classic_sig_size = *(uint32 *)openssl_signature;
  openssl_classic_sig_size = ntohl (openssl_classic_sig_size);

  classic_type = get_pqc_classic_type (EVP_PKEY_id (pqc_hybrid_context));
  switch (classic_type) {
  case pqc_classic_type_none:
    expected_sig_size = openssl_sig_size + sizeof(uint32);
    break;
  case pqc_classic_type_rsa3072:
    expected_sig_size = openssl_sig_size - openssl_classic_sig_size + 384;
    break;
  case pqc_classic_type_p256:
    expected_sig_size = openssl_sig_size - openssl_classic_sig_size + 32 * 2;
    break;
  case pqc_classic_type_p384:
    expected_sig_size = openssl_sig_size - openssl_classic_sig_size + 48 * 2;
    break;
  case pqc_classic_type_p521:
    expected_sig_size = openssl_sig_size - openssl_classic_sig_size + 66 * 2;
    break;
  default:
    return FALSE;
  }

  if (*sig_size < expected_sig_size) {
    *sig_size = expected_sig_size;
    return FALSE;
  }
  *sig_size = expected_sig_size;
  openssl_signature_to_pqc_bin (classic_type, openssl_signature, openssl_sig_size, signature, *sig_size);

  return TRUE;
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
  EVP_MD_CTX *mctx;
  int32      result;
  uint8      openssl_signature[MAC_HYBRID_SIG_SIGNATURE_SIZE];
  uintn      openssl_sig_size;
  pqc_classic_type_t classic_type;
  uintn      max_openssl_sig_size;

  if (pqc_hybrid_context == NULL || message == NULL || signature == NULL) {
    return FALSE;
  }

  if (sig_size > INT_MAX || sig_size == 0) {
    return FALSE;
  }

  classic_type = get_pqc_classic_type (EVP_PKEY_id (pqc_hybrid_context));
  switch (classic_type) {
  case pqc_classic_type_none:
    max_openssl_sig_size = *(uint32 *)signature;
    break;
  case pqc_classic_type_rsa3072:
    max_openssl_sig_size = *(uint32 *)(signature + 384) + sizeof(uint32) + 384;
    break;
  case pqc_classic_type_p256:
    max_openssl_sig_size = *(uint32 *)(signature + 32 * 2) + sizeof(uint32) + 72;
    break;
  case pqc_classic_type_p384:
    max_openssl_sig_size = *(uint32 *)(signature + 48 * 2) + sizeof(uint32) + 104;
    break;
  case pqc_classic_type_p521:
    max_openssl_sig_size = *(uint32 *)(signature + 66 * 2) + sizeof(uint32) + 141;
    break;
  default:
    return FALSE;
  }

  openssl_sig_size = sizeof(openssl_signature);
  ASSERT (openssl_sig_size >= max_openssl_sig_size);
  openssl_signature_from_pqc_bin (classic_type, (uint8 *)signature, sig_size, openssl_signature, &openssl_sig_size);

  mctx = EVP_MD_CTX_new();
  if (mctx == NULL) {
    return FALSE;
  }
  result = EVP_DigestVerifyInit (mctx, NULL, NULL, NULL, pqc_hybrid_context);
  if (result <= 0) {
    return FALSE;
  }
  result = EVP_DigestVerify (mctx, openssl_signature, openssl_sig_size, message, size);

  return (result == 1);
}
