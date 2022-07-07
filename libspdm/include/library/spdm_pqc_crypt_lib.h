/** @file
  SPDM PQC Crypto library.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_PQC_CRYPTO_LIB_H__
#define __SPDM_PQC_CRYPTO_LIB_H__

#include "spdm_lib_config.h"

#include <base.h>
#include <industry_standard/spdm_pqc.h>
#include <library/debuglib.h>
#include <library/memlib.h>
#include <library/cryptlib.h>
#include <library/spdm_crypt_lib.h>

#define MAX_PQC_KEM_SHARED_KEY_SIZE   200

#define MAX_PQC_KEM_PUBLIC_KEY_SIZE_BIKE             6206
#define MAX_PQC_KEM_PUBLIC_KEY_SIZE_CLASSIC_MCELIECE 1357824
#define MAX_PQC_KEM_PUBLIC_KEY_SIZE_HQC              7245
#define MAX_PQC_KEM_PUBLIC_KEY_SIZE_KYBER            1568
#define MAX_PQC_KEM_PUBLIC_KEY_SIZE_SIKE             564
#define MAX_PQC_KEM_PUBLIC_KEY_SIZE   21520 // TBD

#define MAX_PQC_KEM_CIPHER_TEXT_SIZE_BIKE             6206
#define MAX_PQC_KEM_CIPHER_TEXT_SIZE_CLASSIC_MCELIECE 240
#define MAX_PQC_KEM_CIPHER_TEXT_SIZE_HQC              14469
#define MAX_PQC_KEM_CIPHER_TEXT_SIZE_KYBER            1568
#define MAX_PQC_KEM_CIPHER_TEXT_SIZE_SIKE             596
#define MAX_PQC_KEM_CIPHER_TEXT_SIZE  21632 // TBD

#define MAX_PQC_SIG_PUBLIC_KEY_SIZE_DILITHIUM   2592
#define MAX_PQC_SIG_PUBLIC_KEY_SIZE_FALCON      1793
#define MAX_PQC_SIG_PUBLIC_KEY_SIZE_SPHINCS     64
#define MAX_PQC_SIG_PUBLIC_KEY_SIZE   2592 // TBD

#define MAX_PQC_SIG_SIGNATURE_SIZE_DILITHIUM   4595
#define MAX_PQC_SIG_SIGNATURE_SIZE_FALCON      1330
#define MAX_PQC_SIG_SIGNATURE_SIZE_SPHINCS     49216
#define MAX_PQC_SIG_SIGNATURE_SIZE    49216 // TBD

#define PQC_SIG_SIGNATURE_LENGTH_SIZE 4 // 4 bytes to store the real signature length at runtime

uintn
spdm_get_pqc_sig_nid (
  IN   pqc_algo_t     pqc_sig_algo
  );

uintn
spdm_get_pqc_kem_nid (
  IN   pqc_algo_t     pqc_kem_algo
  );

char8 *
spdm_get_pqc_sig_name (
  IN   pqc_algo_t     pqc_sig_algo
  );

char8 *
spdm_get_pqc_kem_name (
  IN   pqc_algo_t     pqc_kem_algo
  );

void
spdm_get_pqc_algo_from_nid (
  IN  uintn            nid,
  OUT pqc_algo_t       pqc_algo
  );

void
spdm_pqc_algo_and (
  IN pqc_algo_t        pqc_algo_1,
  IN pqc_algo_t        pqc_algo_2,
  OUT pqc_algo_t       pqc_algo
  );

void
spdm_pqc_algo_or (
  IN pqc_algo_t        pqc_algo_1,
  IN pqc_algo_t        pqc_algo_2,
  OUT pqc_algo_t       pqc_algo
  );

boolean
spdm_pqc_algo_is_zero (
  IN pqc_algo_t        pqc_algo
  );

/**
  This function returns the SPDM pqc_sig_algo algorithm size.

  @param  pqc_sig_algo                   SPDM pqc_sig_algo

  @return SPDM pqc_sig_algo algorithm size.
**/
uint32
spdm_get_pqc_sig_public_key_size (
  IN   pqc_algo_t     pqc_sig_algo
  );

/**
  This function returns the SPDM pqc_sig_algo algorithm size.

  @param  pqc_sig_algo                   SPDM pqc_sig_algo

  @return SPDM pqc_sig_algo algorithm size.
**/
uint32
spdm_get_pqc_sig_signature_size (
  IN   pqc_algo_t     pqc_sig_algo
  );

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
  );

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
  );

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
  );

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
  );

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
  );

/**
  This function returns the SPDM requester PQC SIG algorithm size.

  @param  pqc_req_sig_algo                SPDM pqc_req_sig_algo

  @return SPDM requester PQC SIG algorithm size.
**/
uint32
spdm_get_pqc_req_sig_public_key_size (
  IN   pqc_algo_t     pqc_req_sig_algo
  );

/**
  This function returns the SPDM requester PQC SIG algorithm size.

  @param  pqc_req_sig_algo                SPDM pqc_req_sig_algo

  @return SPDM requester PQC SIG algorithm size.
**/
uint32
spdm_get_pqc_req_sig_signature_size (
  IN   pqc_algo_t     pqc_req_sig_algo
  );

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
  );

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
  );

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
  );

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
  );

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
  );

/**
  This function returns the SPDM PQC KEM algorithm key size.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo

  @return SPDM PQC KEM algorithm key size.
**/
uint32
spdm_get_pqc_kem_public_key_size (
  IN      pqc_algo_t     pqc_kem_algo
  );

/**
  This function returns the SPDM PQC KEM algorithm key size.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo

  @return SPDM PQC KEM algorithm key size.
**/
uint32
spdm_get_pqc_kem_shared_key_size (
  IN      pqc_algo_t     pqc_kem_algo
  );

/**
  This function returns the SPDM PQC KEM algorithm key size.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo

  @return SPDM PQC KEM algorithm key size.
**/
uint32
spdm_get_pqc_kem_cipher_text_size (
  IN      pqc_algo_t     pqc_kem_algo
  );

/**
  Allocates and Initializes one PQC KEM context for subsequent use,
  based upon negotiated PQC KEM algorithm.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo

  @return  Pointer to the PQC KEM context that has been initialized.
**/
void *
spdm_pqc_kem_new (
  IN      pqc_algo_t     pqc_kem_algo
  );

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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

/**
  Release the specified PQC SIG context,
  based upon negotiated PQC SIG algorithm.

  @param  context                      Pointer to the PQC SIG context.
**/
void
spdm_hybrid_sig_free (
  IN   void         *context
  );

#endif