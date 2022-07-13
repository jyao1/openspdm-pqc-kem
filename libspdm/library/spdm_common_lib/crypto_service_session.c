/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_common_lib_internal.h"

/*
  This function calculates current TH data with message A and message K.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
  @param  cert_chain_data_size            size in bytes of the certitiface chain data.
  @param  th_data_buffer_size             size in bytes of the th_data_buffer
  @param  th_data_buffer                 The buffer to store the th_data_buffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
boolean
spdm_calculate_th_for_exchange (
  IN     void                      *context,
  IN     void                      *spdm_session_info,
  IN     uint8                     *cert_chain_data, OPTIONAL
  IN     uintn                     cert_chain_data_size, OPTIONAL
  IN OUT uintn                     *th_data_buffer_size,
     OUT void                      *th_data_buffer
  )
{
  spdm_context_t           *spdm_context;
  spdm_session_info_t             *session_info;
  uint8                         cert_chain_data_hash[MAX_HASH_SIZE];
  uint32                        hash_size;
  return_status                 status;
  large_managed_buffer_t          th_curr;

  spdm_context = context;
  session_info = spdm_session_info;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  ASSERT (*th_data_buffer_size >= MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE);
  init_managed_buffer (&th_curr, MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE);

  DEBUG((DEBUG_INFO, "message_a data :\n"));
  internal_dump_hex (get_managed_buffer(&spdm_context->transcript.message_a), get_managed_buffer_size(&spdm_context->transcript.message_a));
  status = append_managed_buffer (&th_curr, get_managed_buffer(&spdm_context->transcript.message_a), get_managed_buffer_size(&spdm_context->transcript.message_a));
  if (RETURN_ERROR(status)) {
    return FALSE;
  }

  if (cert_chain_data != NULL) {
    DEBUG((DEBUG_INFO, "th_message_ct data :\n"));
    internal_dump_hex (cert_chain_data, cert_chain_data_size);
    spdm_hash_all (spdm_context->connection_info.algorithm.bash_hash_algo, cert_chain_data, cert_chain_data_size, cert_chain_data_hash);
    status = append_managed_buffer (&th_curr, cert_chain_data_hash, hash_size);
    if (RETURN_ERROR(status)) {
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "message_k data :\n"));
  internal_dump_hex (get_managed_buffer(&session_info->session_transcript.message_k), get_managed_buffer_size(&session_info->session_transcript.message_k));
  status = append_managed_buffer (&th_curr, get_managed_buffer(&session_info->session_transcript.message_k), get_managed_buffer_size(&session_info->session_transcript.message_k));
  if (RETURN_ERROR(status)) {
    return FALSE;
  }

  *th_data_buffer_size = get_managed_buffer_size(&th_curr);
  copy_mem (th_data_buffer, get_managed_buffer(&th_curr), *th_data_buffer_size);

  return TRUE;
}

/*
  This function calculates current TH data with message A, message K and message F.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
  @param  cert_chain_data_size            size in bytes of the certitiface chain data.
  @param  mut_cert_chain_data             Certitiface chain data without spdm_cert_chain_t header in mutual authentication.
  @param  mut_cert_chain_data_size         size in bytes of the certitiface chain data in mutual authentication.
  @param  th_data_buffer_size             size in bytes of the th_data_buffer
  @param  th_data_buffer                 The buffer to store the th_data_buffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
boolean
spdm_calculate_th_for_finish (
  IN     void                      *context,
  IN     void                      *spdm_session_info,
  IN     uint8                     *cert_chain_data, OPTIONAL
  IN     uintn                     cert_chain_data_size, OPTIONAL
  IN     uint8                     *mut_cert_chain_data, OPTIONAL
  IN     uintn                     mut_cert_chain_data_size, OPTIONAL
  IN OUT uintn                     *th_data_buffer_size,
     OUT void                      *th_data_buffer
  )
{
  spdm_context_t           *spdm_context;
  spdm_session_info_t             *session_info;
  uint8                         cert_chain_data_hash[MAX_HASH_SIZE];
  uint8                         MutCertChainDataHash[MAX_HASH_SIZE];
  uint32                        hash_size;
  return_status                 status;
  large_managed_buffer_t          th_curr;

  spdm_context = context;
  session_info = spdm_session_info;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  ASSERT (*th_data_buffer_size >= MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE);
  init_managed_buffer (&th_curr, MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE);

  DEBUG((DEBUG_INFO, "message_a data :\n"));
  internal_dump_hex (get_managed_buffer(&spdm_context->transcript.message_a), get_managed_buffer_size(&spdm_context->transcript.message_a));
  status = append_managed_buffer (&th_curr, get_managed_buffer(&spdm_context->transcript.message_a), get_managed_buffer_size(&spdm_context->transcript.message_a));
  if (RETURN_ERROR(status)) {
    return FALSE;
  }

  if (cert_chain_data != NULL) {
    DEBUG((DEBUG_INFO, "th_message_ct data :\n"));
    internal_dump_hex (cert_chain_data, cert_chain_data_size);
    spdm_hash_all (spdm_context->connection_info.algorithm.bash_hash_algo, cert_chain_data, cert_chain_data_size, cert_chain_data_hash);
    status = append_managed_buffer (&th_curr, cert_chain_data_hash, hash_size);
    if (RETURN_ERROR(status)) {
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "message_k data :\n"));
  internal_dump_hex (get_managed_buffer(&session_info->session_transcript.message_k), get_managed_buffer_size(&session_info->session_transcript.message_k));
  status = append_managed_buffer (&th_curr, get_managed_buffer(&session_info->session_transcript.message_k), get_managed_buffer_size(&session_info->session_transcript.message_k));
  if (RETURN_ERROR(status)) {
    return FALSE;
  }

  if (mut_cert_chain_data != NULL) {
    DEBUG((DEBUG_INFO, "th_message_cm data :\n"));
    internal_dump_hex (mut_cert_chain_data, mut_cert_chain_data_size);
    spdm_hash_all (spdm_context->connection_info.algorithm.bash_hash_algo, mut_cert_chain_data, mut_cert_chain_data_size, MutCertChainDataHash);
    status = append_managed_buffer (&th_curr, MutCertChainDataHash, hash_size);
    if (RETURN_ERROR(status)) {
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "message_f data :\n"));
  internal_dump_hex (get_managed_buffer(&session_info->session_transcript.message_f), get_managed_buffer_size(&session_info->session_transcript.message_f));
  status = append_managed_buffer (&th_curr, get_managed_buffer(&session_info->session_transcript.message_f), get_managed_buffer_size(&session_info->session_transcript.message_f));
  if (RETURN_ERROR(status)) {
    return FALSE;
  }

  *th_data_buffer_size = get_managed_buffer_size(&th_curr);
  copy_mem (th_data_buffer, get_managed_buffer(&th_curr), *th_data_buffer_size);

  return TRUE;
}

/**
  This function generates the key exchange signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  signature                    The buffer to store the key exchange signature.

  @retval TRUE  key exchange signature is generated.
  @retval FALSE key exchange signature is not generated.
**/
boolean
spdm_generate_key_exchange_rsp_signature (
  IN     spdm_context_t       *spdm_context,
  IN     spdm_session_info_t         *session_info,
     OUT uint8                     *signature
  )
{
  uint8                         hash_data[MAX_HASH_SIZE];
  uint8                         *cert_chain_data;
  uintn                         cert_chain_data_size;
  boolean                       result;
  uintn                         asym_signature_size;
  uintn                         pqc_signature_size;
  uint32                        hash_size;
  uint8                         th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                         th_curr_data_size;
  uint32                        *pqc_sigature_length_ptr;
  boolean                       need_pqc_sig;
  boolean                       use_pqc_kem_auth;

  need_pqc_sig = !spdm_pqc_algo_is_zero (spdm_context->connection_info.algorithm.pqc_sig_algo);
  use_pqc_kem_auth = !spdm_pqc_algo_is_zero (spdm_context->connection_info.algorithm.pqc_kem_auth_algo);

  asym_signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo);
  pqc_signature_size = spdm_get_pqc_sig_signature_size (spdm_context->connection_info.algorithm.pqc_sig_algo);

  if (asym_signature_size == 0 && pqc_signature_size == 0) {
    pqc_sigature_length_ptr = (uint32 *)(signature);
    *pqc_sigature_length_ptr = 0;
    return TRUE;
  }

  if (use_pqc_kem_auth && (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW)) {
    need_pqc_sig = FALSE;
    pqc_signature_size = 0;
  }
  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  if (asym_signature_size != 0) {
    result = spdm_get_local_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
      return FALSE;
    }
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_exchange (spdm_context, session_info, cert_chain_data, cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  // debug only
  spdm_hash_all (spdm_context->connection_info.algorithm.bash_hash_algo, th_curr_data, th_curr_data_size, hash_data);
  DEBUG((DEBUG_INFO, "th_curr hash - "));
  internal_dump_data (hash_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  if (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW) {
    if (asym_signature_size != 0) {
      result = spdm_responder_data_sign (
                spdm_context->connection_info.algorithm.base_asym_algo,
                spdm_context->connection_info.algorithm.bash_hash_algo,
                th_curr_data,
                th_curr_data_size,
                signature,
                &asym_signature_size
                );
    } else {
      result = TRUE;
    }
    if (result) {
      DEBUG((DEBUG_INFO, "signature (classical) - "));
      internal_dump_data (signature, asym_signature_size);
      DEBUG((DEBUG_INFO, "\n"));
    } else {
      return FALSE;
    }

    pqc_sigature_length_ptr = (uint32 *)(signature + asym_signature_size);
    if (need_pqc_sig) {
      result = spdm_pqc_responder_data_sign (
                spdm_context->connection_info.algorithm.pqc_sig_algo,
                th_curr_data,
                th_curr_data_size,
                (uint8 *)(pqc_sigature_length_ptr + 1),
                &pqc_signature_size
                );
    } else {
      result = TRUE;
    }
    *pqc_sigature_length_ptr = (uint32)pqc_signature_size;
    if (result) {
      DEBUG((DEBUG_INFO, "signature (PQC) - "));
      internal_dump_data ((uint8 *)(pqc_sigature_length_ptr + 1), pqc_signature_size);
      DEBUG((DEBUG_INFO, "\n"));
    }
  } else {
    asym_signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo) +
                          PQC_SIG_SIGNATURE_LENGTH_SIZE +
                          spdm_get_pqc_sig_signature_size (spdm_context->connection_info.algorithm.pqc_sig_algo);
    result = spdm_hybrid_responder_data_sign (
              spdm_context->connection_info.algorithm.base_asym_algo,
              spdm_context->connection_info.algorithm.bash_hash_algo,
              spdm_context->connection_info.algorithm.pqc_sig_algo,
              th_curr_data,
              th_curr_data_size,
              signature,
              &asym_signature_size
              );
    if (result) {
      DEBUG((DEBUG_INFO, "signature (hybrid) - "));
      internal_dump_data (signature, asym_signature_size);
      DEBUG((DEBUG_INFO, "\n"));
    } else {
      return FALSE;
    }
  }

  return result;
}

/**
  This function generates the key exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the key exchange HMAC.

  @retval TRUE  key exchange HMAC is generated.
  @retval FALSE key exchange HMAC is not generated.
**/
boolean
spdm_generate_key_exchange_rsp_hmac (
  IN     spdm_context_t       *spdm_context,
  IN     spdm_session_info_t         *session_info,
     OUT uint8                     *hmac
  )
{
  uint8                         hmac_data[MAX_HASH_SIZE];
  uint8                         *cert_chain_data;
  uintn                         cert_chain_data_size;
  uint32                        hash_size;
  uint8                         th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                         th_curr_data_size;
  boolean                       result;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  result = spdm_get_local_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
  if (!result) {
    return FALSE;
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_exchange (spdm_context, session_info, cert_chain_data, cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  spdm_hmac_all_with_response_finished_key (session_info->secured_message_context, th_curr_data, th_curr_data_size, hmac_data);
  DEBUG((DEBUG_INFO, "th_curr hmac - "));
  internal_dump_data (hmac_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  copy_mem (hmac, hmac_data, hash_size);

  return TRUE;
}

/**
  This function verifies the key exchange signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean
spdm_verify_key_exchange_rsp_signature (
  IN spdm_context_t          *spdm_context,
  IN spdm_session_info_t            *session_info,
  IN void                         *sign_data,
  IN uintn                        sign_data_size
  )
{
  uintn                                     hash_size;
  uint8                                     hash_data[MAX_HASH_SIZE];
  boolean                                   result;
  boolean                                   result2;
  uintn                                     asym_signature_size;
  uintn                                     pqc_signature_size;
  uint8                                     *cert_chain_data;
  uintn                                     cert_chain_data_size;
  uint8                                     *cert_buffer;
  uintn                                     cert_buffer_size;
  void                                      *context;
  uint8                                     th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                                     th_curr_data_size;
  void                                      *pqc_public_key;
  uintn                                     pqc_public_key_size;
  uint32                                    *pqc_sigature_length_ptr;
  boolean                                   need_pqc_sig;
  boolean                                   use_pqc_kem_auth;

  need_pqc_sig = !spdm_pqc_algo_is_zero (spdm_context->connection_info.algorithm.pqc_sig_algo);
  use_pqc_kem_auth = !spdm_pqc_algo_is_zero (spdm_context->connection_info.algorithm.pqc_kem_auth_algo);

  asym_signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo);
  pqc_signature_size = spdm_get_pqc_sig_signature_size (spdm_context->connection_info.algorithm.pqc_sig_algo);

  if (asym_signature_size == 0 && pqc_signature_size == 0) {
    return TRUE;
  }

  if (use_pqc_kem_auth && (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW)) {
    need_pqc_sig = FALSE;
    pqc_signature_size = 0;
  }
  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  if (sign_data_size != asym_signature_size + PQC_SIG_SIGNATURE_LENGTH_SIZE + pqc_signature_size) {
    return FALSE;
  }

  if (asym_signature_size != 0) {
    result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
      return FALSE;
    }
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_exchange (spdm_context, session_info, cert_chain_data, cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  // debug only
  spdm_hash_all (spdm_context->connection_info.algorithm.bash_hash_algo, th_curr_data, th_curr_data_size, hash_data);
  DEBUG((DEBUG_INFO, "th_curr hash - "));
  internal_dump_data (hash_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  if (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW) {
    DEBUG((DEBUG_INFO, "signature (classical) - "));
    internal_dump_data (sign_data, asym_signature_size);
    DEBUG((DEBUG_INFO, "\n"));

    DEBUG((DEBUG_INFO, "signature (PQC) - "));
    internal_dump_data ((uint8 *)sign_data + asym_signature_size + PQC_SIG_SIGNATURE_LENGTH_SIZE, pqc_signature_size);
    DEBUG((DEBUG_INFO, "\n"));
  } else {
    DEBUG((DEBUG_INFO, "signature (hybrid) - "));
    internal_dump_data (sign_data, asym_signature_size + PQC_SIG_SIGNATURE_LENGTH_SIZE + pqc_signature_size);
    DEBUG((DEBUG_INFO, "\n"));
  }

  //
  // Get leaf cert from cert chain
  //
  if (asym_signature_size != 0) {
    result = x509_get_cert_from_cert_chain (cert_chain_data, cert_chain_data_size, -1,  &cert_buffer, &cert_buffer_size);
    if (!result) {
      return FALSE;
    }
  }
  if (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW) {
    if (asym_signature_size != 0) {
      result = spdm_asym_get_public_key_from_x509 (spdm_context->connection_info.algorithm.base_asym_algo, cert_buffer, cert_buffer_size, &context);
      if (!result) {
        return FALSE;
      }

      result = spdm_asym_verify (
                spdm_context->connection_info.algorithm.base_asym_algo,
                spdm_context->connection_info.algorithm.bash_hash_algo,
                context,
                th_curr_data,
                th_curr_data_size,
                sign_data,
                asym_signature_size
                );
      spdm_asym_free (spdm_context->connection_info.algorithm.base_asym_algo, context);
    } else {
      result = TRUE;
    }
    pqc_sigature_length_ptr = (uint32 *)((uint8 *)sign_data + asym_signature_size);
    if (*pqc_sigature_length_ptr > pqc_signature_size) {
      return FALSE;
    }
    if (need_pqc_sig) {
      result2 = spdm_get_pqc_peer_public_key (spdm_context, &pqc_public_key, &pqc_public_key_size);
      if (!result2) {
        return FALSE;
      }
      result2 = spdm_pqc_sig_set_public_key (spdm_context->connection_info.algorithm.pqc_sig_algo, pqc_public_key, pqc_public_key_size, &context);
      if (!result2) {
        return FALSE;
      }
      result2 = spdm_pqc_sig_verify (
                spdm_context->connection_info.algorithm.pqc_sig_algo,
                context,
                th_curr_data,
                th_curr_data_size,
                (uint8 *)(pqc_sigature_length_ptr + 1),
                *pqc_sigature_length_ptr
                );
      spdm_pqc_sig_free (spdm_context->connection_info.algorithm.pqc_sig_algo, context);
    } else {
      result2 = TRUE;
    }
  } else {
    asym_signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo) +
                          PQC_SIG_SIGNATURE_LENGTH_SIZE +
                          spdm_get_pqc_sig_signature_size (spdm_context->connection_info.algorithm.pqc_sig_algo);

    result = spdm_hybrid_get_public_key_from_x509 (cert_buffer, cert_buffer_size, &context);
    if (!result) {
      return FALSE;
    }

    result = spdm_hybrid_sig_verify (
              context,
              th_curr_data,
              th_curr_data_size,
              sign_data,
              asym_signature_size
              );
    spdm_hybrid_sig_free (context);
  }

  if (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW) {
    if (!result || !result2) {
      if (!result) {
        DEBUG((DEBUG_INFO, "!!! verify_key_exchange_signature (classical) - FAIL !!!\n"));
      }
      if (!result2) {
        DEBUG((DEBUG_INFO, "!!! verify_key_exchange_signature (PQC) - FAIL !!!\n"));
      }
      return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! verify_key_exchange_signature (classical + PQC) - PASS !!!\n"));
  } else {
    if (!result) {
      DEBUG((DEBUG_INFO, "!!! verify_key_exchange_signature (hybrid) - FAIL !!!\n"));
      return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! verify_key_exchange_signature (hybrid) - PASS !!!\n"));
  }

  return TRUE;
}

/**
  This function verifies the key exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean
spdm_verify_key_exchange_rsp_hmac (
  IN     spdm_context_t  *spdm_context,
  IN     spdm_session_info_t    *session_info,
  IN     void                 *hmac_data,
  IN     uintn                hmac_data_size
  )
{
  uintn                                     hash_size;
  uint8                                     calc_hmac_data[MAX_HASH_SIZE];
  uint8                                     *cert_chain_data;
  uintn                                     cert_chain_data_size;
  boolean                                   result;
  uint8                                     th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                                     th_curr_data_size;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  ASSERT(hash_size == hmac_data_size);

  result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
  if (!result) {
    return FALSE;
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_exchange (spdm_context, session_info, cert_chain_data, cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  spdm_hmac_all_with_response_finished_key (session_info->secured_message_context, th_curr_data, th_curr_data_size, calc_hmac_data);
  DEBUG((DEBUG_INFO, "th_curr hmac - "));
  internal_dump_data (calc_hmac_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  if (compare_mem (calc_hmac_data, hmac_data, hash_size) != 0) {
    DEBUG((DEBUG_INFO, "!!! verify_key_exchange_hmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! verify_key_exchange_hmac - PASS !!!\n"));

  return TRUE;
}

/**
  This function generates the finish signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  signature                    The buffer to store the finish signature.

  @retval TRUE  finish signature is generated.
  @retval FALSE finish signature is not generated.
**/
boolean
spdm_generate_finish_req_signature (
  IN     spdm_context_t       *spdm_context,
  IN     spdm_session_info_t         *session_info,
     OUT uint8                     *signature
  )
{
  uint8                         hash_data[MAX_HASH_SIZE];
  uint8                         *cert_chain_data;
  uintn                         cert_chain_data_size;
  uint8                         *mut_cert_chain_data;
  uintn                         mut_cert_chain_data_size;
  boolean                       result;
  uintn                         asym_signature_size;
  uintn                         pqc_signature_size;
  uint32                        hash_size;
  uint8                         th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                         th_curr_data_size;
  uint32                        *pqc_sigature_length_ptr;
  boolean                       need_pqc_req_sig;
  boolean                       use_pqc_req_kem_auth;

  need_pqc_req_sig = !spdm_pqc_algo_is_zero (spdm_context->connection_info.algorithm.pqc_req_sig_algo);
  use_pqc_req_kem_auth = !spdm_pqc_algo_is_zero (spdm_context->connection_info.algorithm.pqc_req_kem_auth_algo);

  asym_signature_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg);
  pqc_signature_size = spdm_get_pqc_req_sig_signature_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo);

  if (asym_signature_size == 0 && pqc_signature_size == 0) {
    pqc_sigature_length_ptr = (uint32 *)(signature);
    *pqc_sigature_length_ptr = 0;
    return TRUE;
  }

  if (use_pqc_req_kem_auth && (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW)) {
    need_pqc_req_sig = FALSE;
    pqc_signature_size = 0;
  }
  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
  if (!result) {
    return FALSE;
  }

  result = spdm_get_local_cert_chain_data (spdm_context, (void **)&mut_cert_chain_data, &mut_cert_chain_data_size);
  if (!result) {
    return FALSE;
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_finish (spdm_context, session_info, cert_chain_data, cert_chain_data_size, mut_cert_chain_data, mut_cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  // debug only
  spdm_hash_all (spdm_context->connection_info.algorithm.bash_hash_algo, th_curr_data, th_curr_data_size, hash_data);
  DEBUG((DEBUG_INFO, "th_curr hash - "));
  internal_dump_data (hash_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  if (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW) {
    if (asym_signature_size != 0) {
      result = spdm_requester_data_sign (
                spdm_context->connection_info.algorithm.req_base_asym_alg,
                spdm_context->connection_info.algorithm.bash_hash_algo,
                th_curr_data,
                th_curr_data_size,
                signature,
                &asym_signature_size
                );
    } else {
      result = TRUE;
    }
    if (result) {
      DEBUG((DEBUG_INFO, "signature (classical) - "));
      internal_dump_data (signature, asym_signature_size);
      DEBUG((DEBUG_INFO, "\n"));
    } else {
      return FALSE;
    }

    pqc_sigature_length_ptr = (uint32 *)(signature + asym_signature_size);
    pqc_signature_size = spdm_get_pqc_req_sig_signature_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo);
    if (need_pqc_req_sig) {
      result = spdm_pqc_requester_data_sign (
                spdm_context->connection_info.algorithm.pqc_req_sig_algo,
                th_curr_data,
                th_curr_data_size,
                (uint8 *)(pqc_sigature_length_ptr + 1),
                &pqc_signature_size
                );
    } else {
      result = TRUE;
    }
    *pqc_sigature_length_ptr = (uint32)pqc_signature_size;
    if (result) {
      DEBUG((DEBUG_INFO, "signature (PQC) - "));
      internal_dump_data ((uint8 *)(pqc_sigature_length_ptr + 1), pqc_signature_size);
      DEBUG((DEBUG_INFO, "\n"));
    }
  } else {
    asym_signature_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg) +
                          PQC_SIG_SIGNATURE_LENGTH_SIZE +
                          spdm_get_pqc_req_sig_signature_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo);
    result = spdm_hybrid_requester_data_sign (
              spdm_context->connection_info.algorithm.req_base_asym_alg,
              spdm_context->connection_info.algorithm.bash_hash_algo,
              spdm_context->connection_info.algorithm.pqc_req_sig_algo,
              th_curr_data,
              th_curr_data_size,
              signature,
              &asym_signature_size
              );
    if (result) {
      DEBUG((DEBUG_INFO, "signature (hybrid) - "));
      internal_dump_data (signature, asym_signature_size);
      DEBUG((DEBUG_INFO, "\n"));
    } else {
      return FALSE;
    }
  }

  return result;
}

/**
  This function generates the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
boolean
spdm_generate_finish_req_hmac (
  IN     spdm_context_t  *spdm_context,
  IN     spdm_session_info_t    *session_info,
     OUT void                 *hmac
  )
{
  uintn                                     hash_size;
  uint8                                     calc_hmac_data[MAX_HASH_SIZE];
  uint8                                     *cert_chain_data;
  uintn                                     cert_chain_data_size;
  uint8                                     *mut_cert_chain_data;
  uintn                                     mut_cert_chain_data_size;
  boolean                                   result;
  uint8                                     th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                                     th_curr_data_size;
  uintn                                     asym_signature_size;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  cert_chain_data = NULL;
  cert_chain_data_size = 0;
  asym_signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo);
  if (asym_signature_size != 0) {
    result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
      return FALSE;
    }
  }

  mut_cert_chain_data = NULL;
  mut_cert_chain_data_size = 0;
  if (session_info->mut_auth_requested) {
    asym_signature_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg);
    if (asym_signature_size != 0) {
      result = spdm_get_local_cert_chain_data (spdm_context, (void **)&mut_cert_chain_data, &mut_cert_chain_data_size);
      if (!result) {
        return FALSE;
      }
    }
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_finish (spdm_context, session_info, cert_chain_data, cert_chain_data_size, mut_cert_chain_data, mut_cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  spdm_hmac_all_with_request_finished_key (session_info->secured_message_context, th_curr_data, th_curr_data_size, calc_hmac_data);
  DEBUG((DEBUG_INFO, "th_curr hmac - "));
  internal_dump_data (calc_hmac_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  copy_mem (hmac, calc_hmac_data, hash_size);

  return TRUE;
}

/**
  This function verifies the finish signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean
spdm_verify_finish_req_signature (
  IN spdm_context_t          *spdm_context,
  IN spdm_session_info_t            *session_info,
  IN void                         *sign_data,
  IN uintn                        sign_data_size
  )
{
  uintn                                     hash_size;
  uint8                                     hash_data[MAX_HASH_SIZE];
  boolean                                   result;
  boolean                                   result2;
  uintn                                     asym_signature_size;
  uintn                                     pqc_signature_size;
  uint8                                     *cert_chain_data;
  uintn                                     cert_chain_data_size;
  uint8                                     *mut_cert_chain_data;
  uintn                                     mut_cert_chain_data_size;
  uint8                                     *mut_cert_buffer;
  uintn                                     mut_cert_buffer_size;
  void                                      *context;
  uint8                                     th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                                     th_curr_data_size;
  void                                      *pqc_public_key;
  uintn                                     pqc_public_key_size;
  uint32                                    *pqc_sigature_length_ptr;
  boolean                                   need_pqc_req_sig;
  boolean                                   use_pqc_req_kem_auth;

  need_pqc_req_sig = !spdm_pqc_algo_is_zero (spdm_context->connection_info.algorithm.pqc_req_sig_algo);
  use_pqc_req_kem_auth = !spdm_pqc_algo_is_zero (spdm_context->connection_info.algorithm.pqc_req_kem_auth_algo);

  asym_signature_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg);
  pqc_signature_size = spdm_get_pqc_req_sig_signature_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo);

  if (asym_signature_size == 0 && pqc_signature_size == 0) {
    return TRUE;
  }

  if (use_pqc_req_kem_auth && (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW)) {
    need_pqc_req_sig = FALSE;
    pqc_signature_size = 0;
  }
  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  if (sign_data_size != asym_signature_size + PQC_SIG_SIGNATURE_LENGTH_SIZE + pqc_signature_size) {
    return FALSE;
  }

  result = spdm_get_local_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
  if (!result) {
    return FALSE;
  }

  result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&mut_cert_chain_data, &mut_cert_chain_data_size);
  if (!result) {
    return FALSE;
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_finish (spdm_context, session_info, cert_chain_data, cert_chain_data_size, mut_cert_chain_data, mut_cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  // debug only
  spdm_hash_all (spdm_context->connection_info.algorithm.bash_hash_algo, th_curr_data, th_curr_data_size, hash_data);
  DEBUG((DEBUG_INFO, "th_curr hash - "));
  internal_dump_data (hash_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  if (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW) {
    DEBUG((DEBUG_INFO, "signature (classical) - "));
    internal_dump_data (sign_data, asym_signature_size);
    DEBUG((DEBUG_INFO, "\n"));

    DEBUG((DEBUG_INFO, "signature (PQC) - "));
    internal_dump_data ((uint8 *)sign_data + asym_signature_size + PQC_SIG_SIGNATURE_LENGTH_SIZE, pqc_signature_size);
    DEBUG((DEBUG_INFO, "\n"));
  } else {
    DEBUG((DEBUG_INFO, "signature (hybrid) - "));
    internal_dump_data (sign_data, asym_signature_size + PQC_SIG_SIGNATURE_LENGTH_SIZE + pqc_signature_size);
    DEBUG((DEBUG_INFO, "\n"));
  }

  //
  // Get leaf cert from cert chain
  //
  if (asym_signature_size != 0) {
    result = x509_get_cert_from_cert_chain (mut_cert_chain_data, mut_cert_chain_data_size, -1,  &mut_cert_buffer, &mut_cert_buffer_size);
    if (!result) {
      return FALSE;
    }
  }

  if (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW) {
    if (asym_signature_size != 0) {
      result = spdm_req_asym_get_public_key_from_x509 (spdm_context->connection_info.algorithm.req_base_asym_alg, mut_cert_buffer, mut_cert_buffer_size, &context);
      if (!result) {
        return FALSE;
      }

      result = spdm_req_asym_verify (
                spdm_context->connection_info.algorithm.req_base_asym_alg,
                spdm_context->connection_info.algorithm.bash_hash_algo,
                context,
                th_curr_data,
                th_curr_data_size,
                sign_data,
                asym_signature_size
                );
      spdm_req_asym_free (spdm_context->connection_info.algorithm.req_base_asym_alg, context);
    } else {
      result = TRUE;
    }

    pqc_sigature_length_ptr = (uint32 *)((uint8 *)sign_data + asym_signature_size);
    if (*pqc_sigature_length_ptr > pqc_signature_size) {
      return FALSE;
    }
    if (need_pqc_req_sig) {
      result2 = spdm_get_pqc_peer_public_key (spdm_context, &pqc_public_key, &pqc_public_key_size);
      if (!result2) {
        return FALSE;
      }
      result2 = spdm_pqc_req_sig_set_public_key (spdm_context->connection_info.algorithm.pqc_req_sig_algo, pqc_public_key, pqc_public_key_size, &context);
      if (!result2) {
        return FALSE;
      }
      result2 = spdm_pqc_req_sig_verify (
                  spdm_context->connection_info.algorithm.pqc_req_sig_algo,
                  context,
                  th_curr_data,
                  th_curr_data_size,
                  (uint8 *)(pqc_sigature_length_ptr + 1),
                  *pqc_sigature_length_ptr
                  );
      spdm_pqc_req_sig_free (spdm_context->connection_info.algorithm.pqc_req_sig_algo, context);
    } else {
      result2 = TRUE;
    }
  } else {
    asym_signature_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg) +
                          PQC_SIG_SIGNATURE_LENGTH_SIZE +
                          spdm_get_pqc_req_sig_signature_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo);
    result = spdm_hybrid_get_public_key_from_x509 (mut_cert_buffer, mut_cert_buffer_size, &context);
    if (!result) {
      return FALSE;
    }

    result = spdm_hybrid_sig_verify (
              context,
              th_curr_data,
              th_curr_data_size,
              sign_data,
              asym_signature_size
              );
    spdm_hybrid_sig_free (context);
  }

  if (spdm_context->local_context.pqc_public_key_mode == SPDM_DATA_PUBLIC_KEY_MODE_RAW) {
    if (!result || !result2) {
      if (!result) {
        DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature (classical) - FAIL !!!\n"));
      }
      if (!result2) {
        DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature (PQC) - FAIL !!!\n"));
      }
      return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature (classical + PQC) - PASS !!!\n"));
  } else {
    if (!result) {
      DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature (hybrid) - FAIL !!!\n"));
      return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature (hybrid) - PASS !!!\n"));
  }

  return TRUE;
}

/**
  This function verifies the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean
spdm_verify_finish_req_hmac (
  IN  spdm_context_t  *spdm_context,
  IN  spdm_session_info_t    *session_info,
  IN  uint8                *hmac,
  IN  uintn                hmac_size
  )
{
  uint8                         hmac_data[MAX_HASH_SIZE];
  uint8                         *cert_chain_data;
  uintn                         cert_chain_data_size;
  uint8                         *mut_cert_chain_data;
  uintn                         mut_cert_chain_data_size;
  uintn                         hash_size;
  boolean                       result;
  uint8                         th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                         th_curr_data_size;
  uintn                         asym_signature_size;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  ASSERT (hmac_size == hash_size);

  cert_chain_data = NULL;
  cert_chain_data_size = 0;
  asym_signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo);
  if (asym_signature_size != 0) {
    result = spdm_get_local_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
      return FALSE;
    }
  }

  mut_cert_chain_data = NULL;
  mut_cert_chain_data_size = 0;
  if (session_info->mut_auth_requested) {
    asym_signature_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg);
    if (asym_signature_size != 0) {
      result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&mut_cert_chain_data, &mut_cert_chain_data_size);
      if (!result) {
        return FALSE;
      }
    }
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_finish (spdm_context, session_info, cert_chain_data, cert_chain_data_size, mut_cert_chain_data, mut_cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  spdm_hmac_all_with_request_finished_key (session_info->secured_message_context, th_curr_data, th_curr_data_size, hmac_data);
  DEBUG((DEBUG_INFO, "th_curr hmac - "));
  internal_dump_data (hmac_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  if (compare_mem(hmac, hmac_data, hash_size) != 0) {
    DEBUG((DEBUG_INFO, "!!! verify_finish_req_hmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! verify_finish_req_hmac - PASS !!!\n"));
  return TRUE;
}

/**
  This function generates the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
boolean
spdm_generate_finish_rsp_hmac (
  IN     spdm_context_t       *spdm_context,
  IN     spdm_session_info_t         *session_info,
     OUT uint8                     *hmac
  )
{
  uint8                         hmac_data[MAX_HASH_SIZE];
  uint8                         *cert_chain_data;
  uintn                         cert_chain_data_size;
  uint8                         *mut_cert_chain_data;
  uintn                         mut_cert_chain_data_size;
  uint32                        hash_size;
  boolean                       result;
  uint8                         th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                         th_curr_data_size;
  uintn                         asym_signature_size;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  cert_chain_data = NULL;
  cert_chain_data_size = 0;
  asym_signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo);
  if (asym_signature_size != 0) {
    result = spdm_get_local_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
      return FALSE;
    }
  }

  mut_cert_chain_data = NULL;
  mut_cert_chain_data_size = 0;
  if (session_info->mut_auth_requested) {
    asym_signature_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg);
    if (asym_signature_size != 0) {
      result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&mut_cert_chain_data, &mut_cert_chain_data_size);
      if (!result) {
        return FALSE;
      }
    }
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_finish (spdm_context, session_info, cert_chain_data, cert_chain_data_size, mut_cert_chain_data, mut_cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  spdm_hmac_all_with_response_finished_key (session_info->secured_message_context, th_curr_data, th_curr_data_size, hmac_data);
  DEBUG((DEBUG_INFO, "th_curr hmac - "));
  internal_dump_data (hmac_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  copy_mem (hmac, hmac_data, hash_size);

  return TRUE;
}

/**
  This function verifies the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean
spdm_verify_finish_rsp_hmac (
  IN     spdm_context_t  *spdm_context,
  IN     spdm_session_info_t    *session_info,
  IN     void                 *hmac_data,
  IN     uintn                hmac_data_size
  )
{
  uintn                                     hash_size;
  uint8                                     calc_hmac_data[MAX_HASH_SIZE];
  uint8                                     *cert_chain_data;
  uintn                                     cert_chain_data_size;
  uint8                                     *mut_cert_chain_data;
  uintn                                     mut_cert_chain_data_size;
  boolean                                   result;
  uint8                                     th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                                     th_curr_data_size;
  uintn                                     asym_signature_size;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  ASSERT(hash_size == hmac_data_size);

  cert_chain_data = NULL;
  cert_chain_data_size = 0;
  asym_signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo);
  if (asym_signature_size != 0) {
    result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
      return FALSE;
    }
  }

  mut_cert_chain_data = NULL;
  mut_cert_chain_data_size = 0;
  if (session_info->mut_auth_requested) {
    asym_signature_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg);
    if (asym_signature_size != 0) {
      result = spdm_get_local_cert_chain_data (spdm_context, (void **)&mut_cert_chain_data, &mut_cert_chain_data_size);
      if (!result) {
        return FALSE;
      }
    }
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_finish (spdm_context, session_info, cert_chain_data, cert_chain_data_size, mut_cert_chain_data, mut_cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  spdm_hmac_all_with_response_finished_key (session_info->secured_message_context, th_curr_data, th_curr_data_size, calc_hmac_data);
  DEBUG((DEBUG_INFO, "th_curr hmac - "));
  internal_dump_data (calc_hmac_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  if (compare_mem (calc_hmac_data, hmac_data, hash_size) != 0) {
    DEBUG((DEBUG_INFO, "!!! verify_finish_rsp_hmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! verify_finish_rsp_hmac - PASS !!!\n"));

  return TRUE;
}

/**
  This function generates the PSK exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the PSK exchange HMAC.

  @retval TRUE  PSK exchange HMAC is generated.
  @retval FALSE PSK exchange HMAC is not generated.
**/
boolean
spdm_generate_psk_exchange_rsp_hmac (
  IN     spdm_context_t       *spdm_context,
  IN     spdm_session_info_t         *session_info,
     OUT uint8                     *hmac
  )
{
  uint8                         hmac_data[MAX_HASH_SIZE];
  uint32                        hash_size;
  boolean                       result;
  uint8                         th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                         th_curr_data_size;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_exchange (spdm_context, session_info, NULL, 0, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  spdm_hmac_all_with_response_finished_key (session_info->secured_message_context, th_curr_data, th_curr_data_size, hmac_data);
  DEBUG((DEBUG_INFO, "th_curr hmac - "));
  internal_dump_data (hmac_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  copy_mem (hmac, hmac_data, hash_size);

  return TRUE;
}

/**
  This function verifies the PSK exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean
spdm_verify_psk_exchange_rsp_hmac (
  IN     spdm_context_t  *spdm_context,
  IN     spdm_session_info_t    *session_info,
  IN     void                 *hmac_data,
  IN     uintn                hmac_data_size
  )
{
  uintn                                     hash_size;
  uint8                                     calc_hmac_data[MAX_HASH_SIZE];
  boolean                                   result;
  uint8                                     th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                                     th_curr_data_size;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  ASSERT(hash_size == hmac_data_size);

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_exchange (spdm_context, session_info, NULL, 0, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  spdm_hmac_all_with_response_finished_key (session_info->secured_message_context, th_curr_data, th_curr_data_size, calc_hmac_data);
  DEBUG((DEBUG_INFO, "th_curr hmac - "));
  internal_dump_data (calc_hmac_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  if (compare_mem (calc_hmac_data, hmac_data, hash_size) != 0) {
    DEBUG((DEBUG_INFO, "!!! verify_psk_exchange_rsp_hmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! verify_psk_exchange_rsp_hmac - PASS !!!\n"));

  return TRUE;
}

/**
  This function generates the PSK finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  PSK finish HMAC is generated.
  @retval FALSE PSK finish HMAC is not generated.
**/
boolean
spdm_generate_psk_exchange_req_hmac (
  IN     spdm_context_t          *spdm_context,
  IN     spdm_session_info_t            *session_info,
     OUT void                         *hmac
  )
{
  uintn                                     hash_size;
  uint8                                     calc_hmac_data[MAX_HASH_SIZE];
  boolean                                   result;
  uint8                                     th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                                     th_curr_data_size;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_finish (spdm_context, session_info, NULL, 0, NULL, 0, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  spdm_hmac_all_with_request_finished_key (session_info->secured_message_context, th_curr_data, th_curr_data_size, calc_hmac_data);
  DEBUG((DEBUG_INFO, "th_curr hmac - "));
  internal_dump_data (calc_hmac_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  copy_mem (hmac, calc_hmac_data, hash_size);

  return TRUE;
}

/**
  This function verifies the PSK finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean
spdm_verify_psk_finish_req_hmac (
  IN  spdm_context_t       *spdm_context,
  IN  spdm_session_info_t         *session_info,
  IN  uint8                     *hmac,
  IN  uintn                     hmac_size
  )
{
  uint8                         hmac_data[MAX_HASH_SIZE];
  uint32                        hash_size;
  boolean                       result;
  uint8                         th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                         th_curr_data_size;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  ASSERT (hmac_size == hash_size);

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_finish (spdm_context, session_info, NULL, 0, NULL, 0, &th_curr_data_size, th_curr_data);
  if (!result) {
    return FALSE;
  }

  spdm_hmac_all_with_request_finished_key (session_info->secured_message_context, th_curr_data, th_curr_data_size, hmac_data);
  DEBUG((DEBUG_INFO, "Calc th_curr hmac - "));
  internal_dump_data (hmac_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  if (compare_mem(hmac, hmac_data, hash_size) != 0) {
    DEBUG((DEBUG_INFO, "!!! verify_psk_finish_req_hmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! verify_psk_finish_req_hmac - PASS !!!\n"));
  return TRUE;
}

/*
  This function calculates th1 hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  is_requester                  Indicate of the key generation for a requester or a responder.
  @param  th1_hash_data                  th1 hash

  @retval RETURN_SUCCESS  th1 hash is calculated.
*/
return_status
spdm_calculate_th1_hash (
  IN void                         *context,
  IN void                         *spdm_session_info,
  IN boolean                      is_requester,
  OUT uint8                       *th1_hash_data
  )
{
  spdm_context_t            *spdm_context;
  uintn                          hash_size;
  uint8                          *cert_chain_data;
  uintn                          cert_chain_data_size;
  spdm_session_info_t              *session_info;
  boolean                        result;
  uint8                          th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                          th_curr_data_size;
  uintn                          asym_signature_size;

  spdm_context = context;

  DEBUG((DEBUG_INFO, "Calc th1 hash ...\n"));

  session_info = spdm_session_info;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  cert_chain_data = NULL;
  cert_chain_data_size = 0;
  if (!session_info->use_psk) {
    asym_signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo);
    if (asym_signature_size != 0) {
      if (is_requester) {
        result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
      } else {
        result = spdm_get_local_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
      }
    } else {
      result = TRUE;
    }
    if (!result) {
      return RETURN_UNSUPPORTED;
    }
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_exchange (spdm_context, session_info, cert_chain_data, cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return RETURN_SECURITY_VIOLATION;
  }

  spdm_hash_all (spdm_context->connection_info.algorithm.bash_hash_algo, th_curr_data, th_curr_data_size, th1_hash_data);
  DEBUG((DEBUG_INFO, "th1 hash - "));
  internal_dump_data (th1_hash_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}

/*
  This function calculates th2 hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  is_requester                  Indicate of the key generation for a requester or a responder.
  @param  th1_hash_data                  th2 hash

  @retval RETURN_SUCCESS  th2 hash is calculated.
*/
return_status
spdm_calculate_th2_hash (
  IN void                         *context,
  IN void                         *spdm_session_info,
  IN boolean                      is_requester,
  OUT uint8                       *th2_hash_data
  )
{
  spdm_context_t            *spdm_context;
  uintn                          hash_size;
  uint8                          *cert_chain_data;
  uintn                          cert_chain_data_size;
  uint8                          *mut_cert_chain_data;
  uintn                          mut_cert_chain_data_size;
  spdm_session_info_t              *session_info;
  boolean                        result;
  uint8                          th_curr_data[MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE];
  uintn                          th_curr_data_size;
  uintn                          asym_signature_size;

  spdm_context = context;

  DEBUG((DEBUG_INFO, "Calc th2 hash ...\n"));

  session_info = spdm_session_info;

  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);

  cert_chain_data = NULL;
  cert_chain_data_size = 0;
  mut_cert_chain_data = NULL;
  mut_cert_chain_data_size = 0;
  if (!session_info->use_psk) {
    asym_signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo);
    if (asym_signature_size != 0) {
      if (is_requester) {
        result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
      } else {
        result = spdm_get_local_cert_chain_data (spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
      }
    } else {
      result = TRUE;
    }
    if (!result) {
      return RETURN_UNSUPPORTED;
    }
    if (session_info->mut_auth_requested) {
      asym_signature_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg);
      if (asym_signature_size != 0) {
        if (is_requester) {
          result = spdm_get_local_cert_chain_data (spdm_context, (void **)&mut_cert_chain_data, &mut_cert_chain_data_size);
        } else {
          result = spdm_get_peer_cert_chain_data (spdm_context, (void **)&mut_cert_chain_data, &mut_cert_chain_data_size);
        }
      } else {
        result = TRUE;
      }
      if (!result) {
        return RETURN_UNSUPPORTED;
      }
    }
  }

  th_curr_data_size = sizeof(th_curr_data);
  result = spdm_calculate_th_for_finish (spdm_context, session_info, cert_chain_data, cert_chain_data_size, mut_cert_chain_data, mut_cert_chain_data_size, &th_curr_data_size, th_curr_data);
  if (!result) {
    return RETURN_SECURITY_VIOLATION;
  }

  spdm_hash_all (spdm_context->connection_info.algorithm.bash_hash_algo, th_curr_data, th_curr_data_size, th2_hash_data);
  DEBUG((DEBUG_INFO, "th2 hash - "));
  internal_dump_data (th2_hash_data, hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}
