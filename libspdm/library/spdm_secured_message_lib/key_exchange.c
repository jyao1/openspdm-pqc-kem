/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_secured_message_lib_internal.h"

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) context for subsequent use,
  based upon negotiated DHE algorithm.
  
  @param  dhe_named_group                SPDM dhe_named_group

  @return  Pointer to the Diffie-Hellman context that has been initialized.
**/
void *
spdm_secured_message_dhe_new (
  IN   uint16                       dhe_named_group
  )
{
  return spdm_dhe_new (dhe_named_group);
}

/**
  Release the specified DHE context,
  based upon negotiated DHE algorithm.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  dhe_context                   Pointer to the DHE context to be released.
**/
void
spdm_secured_message_dhe_free (
  IN   uint16                       dhe_named_group,
  IN   void                         *dhe_context
  )
{
  spdm_dhe_free (dhe_named_group, dhe_context);
}

/**
  Generates DHE public key,
  based upon negotiated DHE algorithm.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter public_key and public_key_size. DH context is updated accordingly.
  If the public_key buffer is too small to hold the public key, FALSE is returned and
  public_key_size is set to the required buffer size to obtain the public key.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  dhe_context                   Pointer to the DHE context.
  @param  public_key                    Pointer to the buffer to receive generated public key.
  @param  public_key_size                On input, the size of public_key buffer in bytes.
                                       On output, the size of data returned in public_key buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  public_key_size is not large enough.
**/
boolean
spdm_secured_message_dhe_generate_key (
  IN      uint16                       dhe_named_group,
  IN OUT  void                         *dhe_context,
  OUT     uint8                        *public_key,
  IN OUT  uintn                        *public_key_size
  )
{
  return spdm_dhe_generate_key (dhe_named_group, dhe_context, public_key, public_key_size);
}

/**
  Computes exchanged common key,
  based upon negotiated DHE algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  dhe_named_group                SPDM dhe_named_group
  @param  dhe_context                   Pointer to the DHE context.
  @param  peer_public_key                Pointer to the peer's public key.
  @param  peer_public_key_size            size of peer's public key in bytes.
  @param  key                          Pointer to the buffer to receive generated key.
  @param  spdm_secured_message_context    A pointer to the SPDM secured message context.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  key_size is not large enough.
**/
boolean
spdm_secured_message_dhe_compute_key (
  IN      uint16                       dhe_named_group,
  IN OUT  void                         *dhe_context,
  IN      const uint8                  *peer_public,
  IN      uintn                        peer_public_size,
  IN OUT  void                         *spdm_secured_message_context
  )
{
  spdm_secured_message_context_t           *secured_message_context;
  uint8                                  final_key[MAX_DHE_KEY_SIZE];
  uintn                                  final_key_size;
  boolean                                ret;

  secured_message_context = spdm_secured_message_context;

  final_key_size = sizeof(final_key);
  ret = spdm_dhe_compute_key (dhe_named_group, dhe_context, peer_public, peer_public_size, final_key, &final_key_size);
  if (!ret) {
    return ret;
  }
  copy_mem (secured_message_context->master_secret.shared_secret, final_key, final_key_size);
  secured_message_context->dhe_key_size = final_key_size;
  return TRUE;
}

/**
  Allocates and Initializes one PQC KEM context for subsequent use,
  based upon negotiated PQC KEM algorithm.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo

  @return  Pointer to the PQC KEM context that has been initialized.
**/
void *
spdm_secured_message_pqc_kem_new (
  IN      pqc_algo_t     pqc_kem_algo
  )
{
  return spdm_pqc_kem_new (pqc_kem_algo);
}

/**
  Release the specified PQC KEM context,
  based upon negotiated PQC KEM algorithm.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo
  @param  context                      Pointer to the PQC KEM context.
**/
void
spdm_secured_message_pqc_kem_free (
  IN      pqc_algo_t     pqc_kem_algo,
  IN      void         *context
  )
{
  spdm_pqc_kem_free (pqc_kem_algo, context);
}

/**
  Generate key pairs.

  @param  context                      Pointer to the PQC KEM context.

  @retval  TRUE   Key pairs are generated.
  @retval  FALSE  Fail to generate the key pairs.
**/
boolean
spdm_secured_message_pqc_kem_generate_key (
  IN      pqc_algo_t     pqc_kem_algo,
  IN      void         *context
  )
{
  return spdm_pqc_kem_generate_key (pqc_kem_algo, context);
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
spdm_secured_message_pqc_kem_get_public_key (
  IN      pqc_algo_t     pqc_kem_algo,
  IN      void         *context,
  OUT     uint8        *public_key,
  IN OUT  uintn        *public_key_size
  )
{
  return spdm_pqc_kem_get_public_key (pqc_kem_algo, context, public_key, public_key_size);
}

/**
  Generate shared key and return the encap data for the shared key with peer public key,
  based upon negotiated PQC KEM algorithm.

  @param  context                      Pointer to the PQC KEM context.
  @param  peer_public_key                Pointer to the peer's public key.
  @param  peer_public_key_size            Size of peer's public key in bytes.
  @param  cipher_text                   Pointer to the buffer to receive encapsulated cipher text for the shared key.
  @param  cipher_text_size               On input, the size of cipher text buffer in bytes.
                                       On output, the size of data returned in cipher text buffer in bytes.

  @retval TRUE   PQC KEM shared key is generated and encapsulated succeeded.
  @retval FALSE  PQC KEM shared key generation failed.
  @retval FALSE  SharedKeySize or CipherTextSize is not large enough.
**/
boolean
spdm_secured_message_pqc_kem_encap (
  IN      pqc_algo_t     pqc_kem_algo,
  IN OUT  void         *context,
  IN      const uint8  *peer_public_key,
  IN      uintn        peer_public_key_size,
  OUT     uint8        *cipher_text,
  IN OUT  uintn        *cipher_text_size,
  IN OUT  void         *spdm_secured_message_context
  )
{
  spdm_secured_message_context_t           *secured_message_context;
  uint8                                    shared_key[MAX_PQC_KEM_SHARED_KEY_SIZE];
  uintn                                    shared_key_size;
  boolean                                  ret;

  secured_message_context = spdm_secured_message_context;

  shared_key_size = MAX_PQC_KEM_SHARED_KEY_SIZE;
  ret = spdm_pqc_kem_encap (pqc_kem_algo, context, peer_public_key, peer_public_key_size,
                            shared_key, &shared_key_size, cipher_text, cipher_text_size);
  if (!ret) {
    return ret;
  }
  copy_mem (secured_message_context->master_secret.shared_secret + secured_message_context->dhe_key_size, shared_key, shared_key_size);
  secured_message_context->pqc_shared_secret_size = shared_key_size;
  return TRUE;
}

/**
  Decap the cipher text to shared key with private key,
  based upon negotiated PQC KEM algorithm.

  @param  pqc_kem_algo                   SPDM pqc_kem_algo
  @param  context                      Pointer to the PQC KEM context.
  @param  cipher_text                   Pointer to the buffer to encapsulated cipher text for the shared key.
  @param  cipher_text_size               The size of cipher text buffer in bytes.

  @retval TRUE   PQC KEM shared key is decapsulated succeeded.
  @retval FALSE  PQC KEM shared key decapsulation failed.
  @retval FALSE  SharedKeySize is not large enough.
**/
boolean
spdm_secured_message_pqc_kem_decap (
  IN      pqc_algo_t     pqc_kem_algo,
  IN OUT  void         *context,
  IN      uint8        *cipher_text,
  IN      uintn        cipher_text_size,
  IN OUT  void         *spdm_secured_message_context
  )
{
  spdm_secured_message_context_t           *secured_message_context;
  uint8                                    shared_key[MAX_PQC_KEM_SHARED_KEY_SIZE];
  uintn                                    shared_key_size;
  boolean                                  ret;

  secured_message_context = spdm_secured_message_context;

  shared_key_size = MAX_PQC_KEM_SHARED_KEY_SIZE;
  ret = spdm_pqc_kem_decap (pqc_kem_algo, context,
                            shared_key, &shared_key_size, cipher_text, cipher_text_size);
  if (!ret) {
    return ret;
  }
  copy_mem (secured_message_context->master_secret.shared_secret + secured_message_context->dhe_key_size, shared_key, shared_key_size);
  secured_message_context->pqc_shared_secret_size = shared_key_size;
  return TRUE;
}

boolean
spdm_secured_message_pqc_kem_auth_set_shared_key (
  IN      pqc_algo_t     pqc_kem_auth_algo,
  IN      uint8          *shared_key,
  IN      uintn          shared_key_size,
  IN OUT  void           *spdm_secured_message_context
  )
{
  spdm_secured_message_context_t           *secured_message_context;

  secured_message_context = spdm_secured_message_context;

  ASSERT (shared_key_size == spdm_get_pqc_kem_shared_key_size(pqc_kem_auth_algo));

  copy_mem (secured_message_context->master_secret.pqc_kem_auth_secret, shared_key, shared_key_size);
  secured_message_context->pqc_kem_auth_shared_secret_size = shared_key_size;
  return TRUE;
}

boolean
spdm_secured_message_pqc_req_kem_auth_set_shared_key (
  IN      pqc_algo_t     pqc_req_kem_auth_algo,
  IN      uint8          *shared_key,
  IN      uintn          shared_key_size,
  IN OUT  void           *spdm_secured_message_context
  )
{
  spdm_secured_message_context_t           *secured_message_context;

  secured_message_context = spdm_secured_message_context;

  ASSERT (shared_key_size == spdm_get_pqc_kem_shared_key_size(pqc_req_kem_auth_algo));

  copy_mem (secured_message_context->master_secret.pqc_req_kem_auth_secret, shared_key, shared_key_size);
  secured_message_context->pqc_req_kem_auth_shared_secret_size = shared_key_size;
  return TRUE;
}
