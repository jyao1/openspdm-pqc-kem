/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_responder_lib_internal.h"

/**
  Process the SPDM CHALLENGE request and return the response.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  request_size                  size in bytes of the request data.
  @param  request                      A pointer to the request data.
  @param  response_size                 size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status
spdm_get_response_challenge_auth (
  IN     void                 *context,
  IN     uintn                request_size,
  IN     void                 *request,
  IN OUT uintn                *response_size,
     OUT void                 *response
  )
{
  spdm_challenge_request_t                    *spdm_request;
  uintn                                     spdm_request_size;
  spdm_challenge_auth_response_t              *spdm_response;
  boolean                                   result;
  uintn                                     signature_size;
  uint8                                     slot_id;
  uint32                                    hash_size;
  uint32                                    measurement_summary_hash_size;
  uint8                                     *ptr;
  uintn                                     total_size;
  spdm_context_t                       *spdm_context;
  spdm_challenge_auth_response_attribute_t    auth_attribute;
  return_status                             status;
  boolean                                   use_pqc_kem_auth;
  uintn                                     pqc_kem_auth_cipher_text_size;
  uint8                                     pqc_kem_auth_shared_key[MAX_PQC_KEM_SHARED_KEY_SIZE];
  uintn                                     pqc_kem_auth_shared_key_size;
  uintn                                     hmac_size;

  spdm_context = context;
  spdm_request = request;

  if (spdm_context->response_state != SPDM_RESPONSE_STATE_NORMAL) {
    return spdm_responder_handle_response_state(spdm_context, spdm_request->header.request_response_code, response_size, response);
  }
  if (!spdm_is_capabilities_flag_supported(spdm_context, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_CHALLENGE, response_size, response);
    return RETURN_SUCCESS;
  }
  if (spdm_context->connection_info.connection_state < SPDM_CONNECTION_STATE_NEGOTIATED) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }

  pqc_kem_auth_cipher_text_size = spdm_get_pqc_kem_cipher_text_size (spdm_context->connection_info.algorithm.pqc_kem_auth_algo);
  pqc_kem_auth_shared_key_size = spdm_get_pqc_kem_shared_key_size (spdm_context->connection_info.algorithm.pqc_kem_auth_algo);
  use_pqc_kem_auth = !spdm_pqc_algo_is_zero (spdm_context->connection_info.algorithm.pqc_kem_auth_algo);

  if (request_size < sizeof(spdm_challenge_request_t) + pqc_kem_auth_cipher_text_size) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
  request_size = sizeof(spdm_challenge_request_t) + pqc_kem_auth_cipher_text_size;
  spdm_request_size = request_size;
  //
  // Cache
  //
  status = spdm_append_message_c (spdm_context, spdm_request, spdm_request_size);
  if (RETURN_ERROR(status)) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }

  slot_id = spdm_request->header.param1;

  if ((slot_id != 0xFF) && (slot_id >= spdm_context->local_context.slot_count)) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }

  signature_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo) +
                   PQC_SIG_SIGNATURE_LENGTH_SIZE;
  if (!use_pqc_kem_auth || (spdm_context->local_context.pqc_public_key_mode != SPDM_DATA_PUBLIC_KEY_MODE_RAW)) {
    signature_size += spdm_get_pqc_sig_signature_size (spdm_context->connection_info.algorithm.pqc_sig_algo);
  }
  hash_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  hmac_size = 0;
  if (use_pqc_kem_auth) {
    hmac_size = hash_size;
  }
  measurement_summary_hash_size = spdm_get_measurement_summary_hash_size (spdm_context, FALSE, spdm_request->header.param2);

  total_size = sizeof(spdm_challenge_auth_response_t) +
              hash_size +
              SPDM_NONCE_SIZE +
              measurement_summary_hash_size +
              sizeof(uint16) +
              spdm_context->local_context.opaque_challenge_auth_rsp_size +
              signature_size +
              hmac_size;

  ASSERT (*response_size >= total_size);
  *response_size = total_size;
  zero_mem (response, *response_size);
  spdm_response = response;

  if (spdm_is_version_supported (spdm_context, SPDM_MESSAGE_VERSION_11)) {
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
  } else {
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
  }
  spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
  auth_attribute.slot_id = (uint8)(slot_id & 0xF);
  auth_attribute.reserved = 0;
  auth_attribute.basic_mut_auth_req = 0;
  if (spdm_is_capabilities_flag_supported(spdm_context, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) &&
      spdm_is_capabilities_flag_supported(spdm_context, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP, 0) &&
      (spdm_is_capabilities_flag_supported(spdm_context, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0) ||
       spdm_is_capabilities_flag_supported(spdm_context, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0))) {
    auth_attribute.basic_mut_auth_req = spdm_context->local_context.basic_mut_auth_requested;
  }
  if (auth_attribute.basic_mut_auth_req != 0) {
    spdm_init_basic_mut_auth_encap_state (context, auth_attribute.basic_mut_auth_req);
  }

  spdm_response->header.param1 = *(uint8 *)&auth_attribute;
  spdm_response->header.param2 = (1 << slot_id);
  if (slot_id == 0xFF) {
    spdm_response->header.param2 = 0;

    slot_id = spdm_context->local_context.provisioned_slot_id;
  }

  ptr = (void *)(spdm_response + 1);
  spdm_generate_cert_chain_hash (spdm_context, slot_id, ptr);
  ptr += hash_size;

  spdm_get_random_number (SPDM_NONCE_SIZE, ptr);
  ptr += SPDM_NONCE_SIZE;

  result = spdm_generate_measurement_summary_hash (spdm_context, FALSE, spdm_request->header.param2, ptr);
  if (!result) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
  ptr += measurement_summary_hash_size;

  *(uint16 *)ptr = (uint16)spdm_context->local_context.opaque_challenge_auth_rsp_size;
  ptr += sizeof(uint16);
  copy_mem (ptr, spdm_context->local_context.opaque_challenge_auth_rsp, spdm_context->local_context.opaque_challenge_auth_rsp_size);
  ptr += spdm_context->local_context.opaque_challenge_auth_rsp_size;

  //
  // Calc Sign
  //
  status = spdm_append_message_c (spdm_context, spdm_response, (uintn)ptr - (uintn)spdm_response);
  if (RETURN_ERROR(status)) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
perf_start (PERF_ID_CHALLENG_SIG_GEN);
  result = spdm_generate_challenge_auth_signature (spdm_context, FALSE, ptr);
perf_stop (PERF_ID_CHALLENG_SIG_GEN);
  if (!result) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_CHALLENGE_AUTH, response_size, response);
    return RETURN_SUCCESS;
  }
  ptr += signature_size;

  if (use_pqc_kem_auth) {
perf_start (PERF_ID_CHALLENG_KEM_AUTH_DECAP);
    DEBUG((DEBUG_INFO, "Calc peer_key PQC_KEM_AUTH (0x%x):\n", pqc_kem_auth_cipher_text_size));
    internal_dump_hex ((uint8 *)request + sizeof(spdm_challenge_request_t), pqc_kem_auth_cipher_text_size);
    result = spdm_pqc_responder_kem_auth_decap (
                spdm_context->connection_info.algorithm.pqc_kem_auth_algo,
                (uint8 *)request + sizeof(spdm_challenge_request_t),
                pqc_kem_auth_cipher_text_size,
                pqc_kem_auth_shared_key,
                &pqc_kem_auth_shared_key_size);
    ASSERT(result);
    DEBUG((DEBUG_INFO, "Calc shared_key PQC_KEM_AUTH (0x%x):\n", pqc_kem_auth_shared_key_size));
    internal_dump_hex (pqc_kem_auth_shared_key, pqc_kem_auth_shared_key_size);
perf_stop (PERF_ID_CHALLENG_KEM_AUTH_DECAP);

    status = spdm_append_message_c (spdm_context, ptr - signature_size, signature_size);
    ASSERT (status == RETURN_SUCCESS);
    result = spdm_generate_challenge_auth_hmac (spdm_context, FALSE, ptr,
                pqc_kem_auth_shared_key, pqc_kem_auth_shared_key_size);
    ASSERT (result);
    DEBUG((DEBUG_INFO, "Calc challenge verify_data (0x%x):\n", hash_size));
    internal_dump_hex (ptr, hash_size);
  }


  if (auth_attribute.basic_mut_auth_req == 0) {
    spdm_set_connection_state (spdm_context, SPDM_CONNECTION_STATE_AUTHENTICATED);
  }

  return RETURN_SUCCESS;
}
