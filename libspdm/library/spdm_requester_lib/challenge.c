/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_requester_lib_internal.h"

#pragma pack(1)

typedef struct {
  spdm_message_header_t  header;
  // param1 == slot_id
  // param2 == HashType
  uint8                nonce[32];
  uint8                kem_cipher_text[MAX_PQC_KEM_CIPHER_TEXT_SIZE];
} spdm_challenge_request_max_t;

typedef struct {
  spdm_message_header_t  header;
  uint8                cert_chain_hash[MAX_HASH_SIZE];
  uint8                nonce[SPDM_NONCE_SIZE];
  uint8                measurement_summary_hash[MAX_HASH_SIZE];
  uint16               opaque_length;
  uint8                opaque_data[MAX_SPDM_OPAQUE_DATA_SIZE];
  uint8                signature[MAX_ASYM_KEY_SIZE + PQC_SIG_SIGNATURE_LENGTH_SIZE + MAX_PQC_SIG_SIGNATURE_SIZE];
  uint8                mac[MAX_HASH_SIZE];
} spdm_challenge_auth_response_max_t;

#pragma pack()

/**
  This function sends CHALLENGE
  to authenticate the device based upon the key in one slot.

  This function verifies the signature in the challenge auth.

  If basic mutual authentication is requested from the responder,
  this function also perform the basic mutual authentication.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                      The number of slot for the challenge.
  @param  measurement_hash_type          The type of the measurement hash.
  @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.

  @retval RETURN_SUCCESS               The challenge auth is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status
try_spdm_challenge (
  IN     void                 *context,
  IN     uint8                slot_id,
  IN     uint8                measurement_hash_type,
     OUT void                 *measurement_hash
  )
{
  return_status                             status;
  boolean                                   result;
  spdm_challenge_request_max_t                spdm_request;
  spdm_challenge_auth_response_max_t          spdm_response;
  uintn                                     spdm_request_size;
  uintn                                     spdm_response_size;
  uint8                                     *ptr;
  void                                      *cert_chain_hash;
  uintn                                     hash_size;
  uintn                                     measurement_summary_hash_size;
  void                                      *nonce;
  void                                      *measurement_summary_hash;
  uint16                                    opaque_length;
  void                                      *opaque;
  void                                      *signature;
  uintn                                     signature_size;
  spdm_context_t                       *spdm_context;
  spdm_challenge_auth_response_attribute_t    auth_attribute;
  boolean                                   use_pqc_kem_auth;
  uintn                                     pqc_kem_auth_cipher_text_size;
  uint8                                     pqc_kem_auth_shared_key[MAX_PQC_KEM_SHARED_KEY_SIZE];
  uintn                                     pqc_kem_auth_shared_key_size;
  uintn                                     hmac_size;

  spdm_context = context;
  if (!spdm_is_capabilities_flag_supported(spdm_context, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
    return RETURN_UNSUPPORTED;
  }
  if (spdm_context->connection_info.connection_state < SPDM_CONNECTION_STATE_NEGOTIATED) {
    return RETURN_UNSUPPORTED;
  }

  if ((slot_id >= MAX_SPDM_SLOT_COUNT) && (slot_id != 0xFF)) {
    return RETURN_INVALID_PARAMETER;
  }
  if ((slot_id == 0xFF) && (spdm_context->local_context.peer_cert_chain_provision_size == 0)) {
//    return RETURN_INVALID_PARAMETER;
  }

  spdm_context->error_state = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  if (spdm_is_version_supported (spdm_context, SPDM_MESSAGE_VERSION_11)) {
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
  } else {
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
  }
  spdm_request.header.request_response_code = SPDM_CHALLENGE;
  spdm_request.header.param1 = slot_id;
  spdm_request.header.param2 = measurement_hash_type;
  spdm_get_random_number (SPDM_NONCE_SIZE, spdm_request.nonce);
  DEBUG((DEBUG_INFO, "ClientNonce - "));
  internal_dump_data (spdm_request.nonce, SPDM_NONCE_SIZE);
  DEBUG((DEBUG_INFO, "\n"));

  spdm_request_size = sizeof(spdm_challenge_request_t);

  pqc_kem_auth_cipher_text_size = spdm_get_pqc_kem_cipher_text_size (spdm_context->connection_info.algorithm.pqc_kem_auth_algo);
  pqc_kem_auth_shared_key_size = spdm_get_pqc_kem_shared_key_size (spdm_context->connection_info.algorithm.pqc_kem_auth_algo);
  use_pqc_kem_auth = !spdm_pqc_algo_is_zero (spdm_context->connection_info.algorithm.pqc_kem_auth_algo);
  if (use_pqc_kem_auth) {
    // BUGBUG: This is a hack. We notice that the first KEM call is always time consuming.
    // Maybe it is because the code is not loaded to cache, or the RNG delay.
    // Need further investigation. It becomes normal since second KEM call.
    result = spdm_pqc_responder_kem_auth_encap (
                spdm_context->connection_info.algorithm.pqc_kem_auth_algo,
                spdm_context->local_context.pqc_peer_kem_auth_public_key_provision,
                spdm_context->local_context.pqc_peer_kem_auth_public_key_provision_size,
                spdm_request.kem_cipher_text,
                &pqc_kem_auth_cipher_text_size,
                pqc_kem_auth_shared_key,
                &pqc_kem_auth_shared_key_size);
perf_start (PERF_ID_CHALLENG_KEM_AUTH_ENCAP);
    result = spdm_pqc_responder_kem_auth_encap (
                spdm_context->connection_info.algorithm.pqc_kem_auth_algo,
                spdm_context->local_context.pqc_peer_kem_auth_public_key_provision,
                spdm_context->local_context.pqc_peer_kem_auth_public_key_provision_size,
                spdm_request.kem_cipher_text,
                &pqc_kem_auth_cipher_text_size,
                pqc_kem_auth_shared_key,
                &pqc_kem_auth_shared_key_size);
perf_stop (PERF_ID_CHALLENG_KEM_AUTH_ENCAP);
    ASSERT(result);
    DEBUG((DEBUG_INFO, "ClientKey PQC_KEM_AUTH (0x%x):\n", pqc_kem_auth_cipher_text_size));
    internal_dump_hex (spdm_request.kem_cipher_text, pqc_kem_auth_cipher_text_size);

    DEBUG((DEBUG_INFO, "shared_key PQC_KEM_AUTH (0x%x):\n", pqc_kem_auth_shared_key_size));
    internal_dump_hex (pqc_kem_auth_shared_key, pqc_kem_auth_shared_key_size);

    spdm_request_size += pqc_kem_auth_cipher_text_size;
  }

  status = spdm_send_spdm_request (spdm_context, NULL, spdm_request_size, &spdm_request);
  if (RETURN_ERROR(status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  status = spdm_append_message_c (spdm_context, &spdm_request, spdm_request_size);
  if (RETURN_ERROR(status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  spdm_response_size = sizeof(spdm_response);
  zero_mem (&spdm_response, sizeof(spdm_response));
  status = spdm_receive_spdm_fragment_encap_response (spdm_context, NULL, &spdm_response_size, &spdm_response);
  if (RETURN_ERROR(status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response_size < sizeof(spdm_message_header_t)) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response.header.request_response_code == SPDM_ERROR) {
    status = spdm_handle_error_response_main(spdm_context, NULL, &spdm_context->transcript.message_c, spdm_request_size, &spdm_response_size, &spdm_response, SPDM_CHALLENGE, SPDM_CHALLENGE_AUTH, sizeof(spdm_challenge_auth_response_max_t));
    if (RETURN_ERROR(status)) {
      return status;
    }
  } else if (spdm_response.header.request_response_code != SPDM_CHALLENGE_AUTH) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response_size < sizeof(spdm_challenge_auth_response_t)) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response_size > sizeof(spdm_response)) {
    return RETURN_DEVICE_ERROR;
  }
  *(uint8 *)&auth_attribute = spdm_response.header.param1;
  if (slot_id == 0xFF) {
    if (auth_attribute.slot_id != 0xF) {
      return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.param2 != 0) {
      return RETURN_DEVICE_ERROR;
    }
  } else {
    if (auth_attribute.slot_id != slot_id) {
      return RETURN_DEVICE_ERROR;
    }
    if (spdm_response.header.param2 != (1 << slot_id)) {
      return RETURN_DEVICE_ERROR;
    }
  }
  if (auth_attribute.basic_mut_auth_req == 1) {
    if (!spdm_is_capabilities_flag_supported(spdm_context, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
      return RETURN_DEVICE_ERROR;
    }
  }
  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo) +
                   PQC_SIG_SIGNATURE_LENGTH_SIZE;
  if (!use_pqc_kem_auth || (spdm_context->local_context.pqc_public_key_mode != SPDM_DATA_PUBLIC_KEY_MODE_RAW)) {
    signature_size += spdm_get_pqc_sig_signature_size (spdm_context->connection_info.algorithm.pqc_sig_algo);
  }
  hmac_size = 0;
  if (use_pqc_kem_auth) {
    hmac_size = hash_size;
  }
  measurement_summary_hash_size = spdm_get_measurement_summary_hash_size (spdm_context, TRUE, measurement_hash_type);

  if (spdm_response_size <= sizeof(spdm_challenge_auth_response_t) +
                          hash_size +
                          SPDM_NONCE_SIZE +
                          measurement_summary_hash_size +
                          sizeof(uint16)) {
    return RETURN_DEVICE_ERROR;
  }

  ptr = spdm_response.cert_chain_hash;

  cert_chain_hash = ptr;
  ptr += hash_size;
  DEBUG((DEBUG_INFO, "cert_chain_hash (0x%x) - ", hash_size));
  internal_dump_data (cert_chain_hash, hash_size);
  DEBUG((DEBUG_INFO, "\n"));
  if (spdm_context->local_context.peer_cert_chain_provision_size != 0) {
    result = spdm_verify_certificate_chain_hash (spdm_context, cert_chain_hash, hash_size);
    if (!result) {
      spdm_context->error_state = SPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
      return RETURN_SECURITY_VIOLATION;
    }
  }

  nonce = ptr;
  DEBUG((DEBUG_INFO, "nonce (0x%x) - ", SPDM_NONCE_SIZE));
  internal_dump_data (nonce, SPDM_NONCE_SIZE);
  DEBUG((DEBUG_INFO, "\n"));
  ptr += SPDM_NONCE_SIZE;

  measurement_summary_hash = ptr;
  ptr += measurement_summary_hash_size;
  DEBUG((DEBUG_INFO, "measurement_summary_hash (0x%x) - ", measurement_summary_hash_size));
  internal_dump_data (measurement_summary_hash, measurement_summary_hash_size);
  DEBUG((DEBUG_INFO, "\n"));

  opaque_length = *(uint16 *)ptr;
  if (opaque_length > MAX_SPDM_OPAQUE_DATA_SIZE) {
    return RETURN_SECURITY_VIOLATION;
  }
  ptr += sizeof(uint16);

  if (spdm_response_size < sizeof(spdm_challenge_auth_response_t) +
                         hash_size +
                         SPDM_NONCE_SIZE +
                         measurement_summary_hash_size +
                         sizeof(uint16) +
                         opaque_length +
                         signature_size +
                         hmac_size) {
    return RETURN_DEVICE_ERROR;
  }
  spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                     hash_size +
                     SPDM_NONCE_SIZE +
                     measurement_summary_hash_size +
                     sizeof(uint16) +
                     opaque_length +
                     signature_size +
                     hmac_size;
  status = spdm_append_message_c (spdm_context, &spdm_response, spdm_response_size - signature_size - hmac_size);
  if (RETURN_ERROR(status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  opaque = ptr;
  ptr += opaque_length;
  DEBUG((DEBUG_INFO, "opaque (0x%x):\n", opaque_length));
  internal_dump_hex (opaque, opaque_length);

  signature = ptr;
  DEBUG((DEBUG_INFO, "signature (0x%x):\n", signature_size));
  internal_dump_hex (signature, signature_size);
  ptr += signature_size;
perf_start (PERF_ID_CHALLENG_SIG_VER);
  result = spdm_verify_challenge_auth_signature (spdm_context, TRUE, signature, signature_size);
perf_stop (PERF_ID_CHALLENG_SIG_VER);
  if (!result) {
    spdm_context->error_state = SPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  if (use_pqc_kem_auth) {
    status = spdm_append_message_c (spdm_context, signature, signature_size);
    ASSERT (status == RETURN_SUCCESS);

    DEBUG((DEBUG_INFO, "challenge verify_data (0x%x):\n", hmac_size));
    internal_dump_hex (ptr, hmac_size);

    result = spdm_verify_challenge_auth_hmac (spdm_context, FALSE, ptr,
                pqc_kem_auth_shared_key, pqc_kem_auth_shared_key_size);
    ASSERT (result);
  }

  spdm_context->error_state = SPDM_STATUS_SUCCESS;

  if (measurement_hash != NULL) {
    copy_mem (measurement_hash, measurement_summary_hash, measurement_summary_hash_size);
  }

  if (auth_attribute.basic_mut_auth_req == 1) {
    DEBUG((DEBUG_INFO, "BasicMutAuth :\n"));
    status = spdm_encapsulated_request (spdm_context, NULL, 0, NULL);
    DEBUG ((DEBUG_INFO, "spdm_challenge - spdm_encapsulated_request - %p\n", status));
    if (RETURN_ERROR(status)) {
      spdm_context->error_state = SPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
      return RETURN_SECURITY_VIOLATION;
    }
  }

  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AUTHENTICATED;

  return RETURN_SUCCESS;
}

/**
  This function sends CHALLENGE
  to authenticate the device based upon the key in one slot.

  This function verifies the signature in the challenge auth.

  If basic mutual authentication is requested from the responder,
  this function also perform the basic mutual authentication.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_id                      The number of slot for the challenge.
  @param  measurement_hash_type          The type of the measurement hash.
  @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.

  @retval RETURN_SUCCESS               The challenge auth is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status
spdm_challenge (
  IN     void                 *context,
  IN     uint8                slot_id,
  IN     uint8                measurement_hash_type,
     OUT void                 *measurement_hash
  )
{
  spdm_context_t    *spdm_context;
  uintn                   retry;
  return_status           status;

  spdm_context = context;
  retry = spdm_context->retry_times;
  do {
    status = try_spdm_challenge(spdm_context, slot_id, measurement_hash_type, measurement_hash);
    if (RETURN_NO_RESPONSE != status) {
      return status;
    }
  } while (retry-- != 0);

  return status;
}

