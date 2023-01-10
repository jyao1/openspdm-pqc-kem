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
  uint16               length;
  uint8                measurement_specification;
  uint8                reserved;
  uint32               base_asym_algo;
  uint32               bash_hash_algo;
  uint8                reserved2[12];
  uint8                ext_asym_count;
  uint8                ext_hash_count;
  uint16               reserved3;
  spdm_negotiate_algorithms_common_struct_table_t  struct_table[4];
  spdm_negotiate_algorithms_pqc_struct_table_t     pqc_struct_table[3];
  spdm_negotiate_algorithms_pqc_struct_table_t     pqc_kem_auth_struct_table[2];
} spdm_negotiate_algorithms_request_mine_t;

typedef struct {
  spdm_message_header_t  header;
  uint16               length;
  uint8                measurement_specification_sel;
  uint8                reserved;
  uint32               measurement_hash_algo;
  uint32               base_asym_sel;
  uint32               base_hash_sel;
  uint8                reserved2[12];
  uint8                ext_asym_sel_count;
  uint8                ext_hash_sel_count;
  uint16               reserved3;
  uint32               ext_asym_sel[8];
  uint32               ext_hash_sel[8];
  spdm_negotiate_algorithms_common_struct_table_t  struct_table[4];
  spdm_negotiate_algorithms_pqc_struct_table_t     pqc_struct_table[3];
  spdm_negotiate_algorithms_pqc_struct_table_t     pqc_kem_auth_struct_table[2];
} spdm_algorithms_response_max_t;
#pragma pack()

/**
  This function sends NEGOTIATE_ALGORITHMS and receives ALGORITHMS.

  @param  spdm_context                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The NEGOTIATE_ALGORITHMS is sent and the ALGORITHMS is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status
try_spdm_negotiate_algorithms (
  IN     spdm_context_t  *spdm_context
  )
{
  return_status                                  status;
  spdm_negotiate_algorithms_request_mine_t         spdm_request;
  spdm_algorithms_response_max_t                   spdm_response;
  uintn                                          spdm_response_size;
  uint32                                         algo_size;
  uintn                                          index;
  spdm_negotiate_algorithms_struct_table_t  *struct_table;
  uint8                                          fixed_alg_size;
  uint8                                          ext_alg_count;

  if (spdm_context->connection_info.connection_state != SPDM_CONNECTION_STATE_AFTER_CAPABILITIES) {
    return RETURN_UNSUPPORTED;
  }

  zero_mem (&spdm_request, sizeof(spdm_request));
  if (spdm_is_version_supported (spdm_context, SPDM_MESSAGE_VERSION_11)) {
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.length = sizeof(spdm_request);
    spdm_request.header.param1 = ARRAY_SIZE(spdm_request.struct_table) + ARRAY_SIZE(spdm_request.pqc_struct_table)
                                 + ARRAY_SIZE(spdm_request.pqc_kem_auth_struct_table);
  } else {
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.length = sizeof(spdm_request) - sizeof(spdm_request.struct_table)
                          - sizeof(spdm_request.pqc_struct_table) - sizeof(spdm_request.pqc_kem_auth_struct_table);
    spdm_request.header.param1 = 0;
  }
  spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
  spdm_request.header.param2 = 0;
  spdm_request.measurement_specification = spdm_context->local_context.algorithm.measurement_spec;
  spdm_request.base_asym_algo = spdm_context->local_context.algorithm.base_asym_algo;
  spdm_request.bash_hash_algo = spdm_context->local_context.algorithm.bash_hash_algo;
  spdm_request.ext_asym_count = 0;
  spdm_request.ext_hash_count = 0;
  spdm_request.struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
  spdm_request.struct_table[0].alg_count = 0x20;
  spdm_request.struct_table[0].alg_supported = spdm_context->local_context.algorithm.dhe_named_group;
  spdm_request.struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
  spdm_request.struct_table[1].alg_count = 0x20;
  spdm_request.struct_table[1].alg_supported = spdm_context->local_context.algorithm.aead_cipher_suite;
  spdm_request.struct_table[2].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
  spdm_request.struct_table[2].alg_count = 0x20;
  spdm_request.struct_table[2].alg_supported = spdm_context->local_context.algorithm.req_base_asym_alg;
  spdm_request.struct_table[3].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
  spdm_request.struct_table[3].alg_count = 0x20;
  spdm_request.struct_table[3].alg_supported = spdm_context->local_context.algorithm.key_schedule;
  spdm_request.pqc_struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_DIGITAL_SIGNATURE_ALGO;
  spdm_request.pqc_struct_table[0].alg_count = (uint8)(sizeof(pqc_algo_t) << 4);
  copy_mem (spdm_request.pqc_struct_table[0].alg_supported, spdm_context->local_context.algorithm.pqc_sig_algo, sizeof(pqc_algo_t));
  spdm_request.pqc_struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_REQ_DIGITAL_SIGNATURE_ALGO;
  spdm_request.pqc_struct_table[1].alg_count = (uint8)(sizeof(pqc_algo_t) << 4);
  copy_mem (spdm_request.pqc_struct_table[1].alg_supported, spdm_context->local_context.algorithm.pqc_req_sig_algo, sizeof(pqc_algo_t));
  spdm_request.pqc_struct_table[2].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_KEY_ESTABLISHMENT_ALGO;
  spdm_request.pqc_struct_table[2].alg_count = (uint8)(sizeof(pqc_algo_t) << 4);
  copy_mem (spdm_request.pqc_struct_table[2].alg_supported, spdm_context->local_context.algorithm.pqc_kem_algo, sizeof(pqc_algo_t));
  spdm_request.pqc_kem_auth_struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_KEM_AUTH_ALGO;
  spdm_request.pqc_kem_auth_struct_table[0].alg_count = (uint8)(sizeof(pqc_algo_t) << 4);
  copy_mem (spdm_request.pqc_kem_auth_struct_table[0].alg_supported, spdm_context->local_context.algorithm.pqc_kem_auth_algo, sizeof(pqc_algo_t));
  spdm_request.pqc_kem_auth_struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_REQ_KEM_AUTH_ALGO;
  spdm_request.pqc_kem_auth_struct_table[1].alg_count = (uint8)(sizeof(pqc_algo_t) << 4);
  copy_mem (spdm_request.pqc_kem_auth_struct_table[1].alg_supported, spdm_context->local_context.algorithm.pqc_req_kem_auth_algo, sizeof(pqc_algo_t));

  status = spdm_send_spdm_request (spdm_context, NULL, spdm_request.length, &spdm_request);
  if (RETURN_ERROR(status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  status = spdm_append_message_a (spdm_context, &spdm_request, spdm_request.length);
  if (RETURN_ERROR(status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  spdm_response_size = sizeof(spdm_response);
  zero_mem (&spdm_response, sizeof(spdm_response));
  status = spdm_receive_spdm_response (spdm_context, NULL, &spdm_response_size, &spdm_response);
  if (RETURN_ERROR(status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response_size < sizeof(spdm_message_header_t)) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response.header.request_response_code == SPDM_ERROR) {
    shrink_managed_buffer(&spdm_context->transcript.message_a, spdm_request.length);
    status = spdm_handle_simple_error_response(spdm_context, spdm_response.header.param1);
    if (RETURN_ERROR(status)) {
      return status;
    }
  } else if (spdm_response.header.request_response_code != SPDM_ALGORITHMS) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response_size < sizeof(spdm_algorithms_response_t)) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response_size > sizeof(spdm_response)) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response.ext_asym_sel_count > 1) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response.ext_hash_sel_count > 1) {
    return RETURN_DEVICE_ERROR;
  }
  if (spdm_response_size < sizeof(spdm_algorithms_response_t) + 
                         sizeof(uint32) * spdm_response.ext_asym_sel_count +
                         sizeof(uint32) * spdm_response.ext_hash_sel_count +
                         sizeof(spdm_negotiate_algorithms_struct_table_t) * spdm_response.header.param1) {
    return RETURN_DEVICE_ERROR;
  }
  struct_table = (void *)((uintn)&spdm_response +
                            sizeof(spdm_algorithms_response_t) +
                            sizeof(uint32) * spdm_response.ext_asym_sel_count +
                            sizeof(uint32) * spdm_response.ext_hash_sel_count
                            );
  if (spdm_response.header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
    for (index = 0; index < spdm_response.header.param1; index++) {
      if ((uintn)&spdm_response + spdm_response_size < (uintn)struct_table) {
        return RETURN_DEVICE_ERROR;
      }
      fixed_alg_size = (struct_table->alg_count >> 4) & 0xF;
      ext_alg_count = struct_table->alg_count & 0xF;
      if ((uintn)&spdm_response + spdm_response_size - (uintn)struct_table < sizeof(spdm_negotiate_algorithms_struct_table_t) + fixed_alg_size) {
        return RETURN_DEVICE_ERROR;
      }
      if (fixed_alg_size == 2) {
        switch (struct_table->alg_type) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
          break;
        default:
          return RETURN_DEVICE_ERROR;
        }
      } else if (fixed_alg_size == sizeof(pqc_algo_t)) {
        switch (struct_table->alg_type) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_DIGITAL_SIGNATURE_ALGO:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_REQ_DIGITAL_SIGNATURE_ALGO:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_KEY_ESTABLISHMENT_ALGO:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_KEM_AUTH_ALGO:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_REQ_KEM_AUTH_ALGO:
          break;
        default:
          return RETURN_DEVICE_ERROR;
        }
      } else {
        return RETURN_DEVICE_ERROR;
      }
      if (ext_alg_count > 1) {
        return RETURN_DEVICE_ERROR;
      }
      if ((uintn)&spdm_response + spdm_response_size - (uintn)struct_table - sizeof(spdm_negotiate_algorithms_struct_table_t) - fixed_alg_size < sizeof(uint32) * ext_alg_count) {
        return RETURN_DEVICE_ERROR;
      }
      struct_table = (void *)((uintn)struct_table + sizeof (spdm_negotiate_algorithms_struct_table_t) + fixed_alg_size + sizeof(uint32) * ext_alg_count);
    }
  }
  spdm_response_size = (uintn)struct_table - (uintn)&spdm_response;
  if (spdm_response_size != spdm_response.length) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  status = spdm_append_message_a (spdm_context, &spdm_response, spdm_response_size);
  if (RETURN_ERROR(status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  spdm_context->connection_info.algorithm.measurement_spec = spdm_response.measurement_specification_sel;
  spdm_context->connection_info.algorithm.measurement_hash_algo = spdm_response.measurement_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = spdm_response.base_asym_sel;
  spdm_context->connection_info.algorithm.bash_hash_algo = spdm_response.base_hash_sel;

  if (spdm_is_capabilities_flag_supported(spdm_context, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
    if (spdm_context->connection_info.algorithm.measurement_spec != SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
      return RETURN_SECURITY_VIOLATION;
    }
    algo_size = spdm_get_measurement_hash_size (spdm_context->connection_info.algorithm.measurement_hash_algo);
    if (algo_size == 0) {
      return RETURN_SECURITY_VIOLATION;
    }
  }
  algo_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  if (algo_size == 0) {
    return RETURN_SECURITY_VIOLATION;
  }
  if (spdm_is_capabilities_flag_supported(spdm_context, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
    algo_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo);
    if (algo_size == 0) {
//      return RETURN_SECURITY_VIOLATION;
    }
  }

  if (spdm_response.header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
    struct_table = (void *)((uintn)&spdm_response +
                            sizeof(spdm_algorithms_response_t) +
                            sizeof(uint32) * spdm_response.ext_asym_sel_count +
                            sizeof(uint32) * spdm_response.ext_hash_sel_count
                            );
    for (index = 0; index < spdm_response.header.param1; index++) {
      switch (struct_table->alg_type) {
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
        spdm_context->connection_info.algorithm.dhe_named_group = *(uint16 *)(struct_table + 1);
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
        spdm_context->connection_info.algorithm.aead_cipher_suite = *(uint16 *)(struct_table + 1);
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
        spdm_context->connection_info.algorithm.req_base_asym_alg = *(uint16 *)(struct_table + 1);
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
        spdm_context->connection_info.algorithm.key_schedule = *(uint16 *)(struct_table + 1);
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_DIGITAL_SIGNATURE_ALGO:
        copy_mem (spdm_context->connection_info.algorithm.pqc_sig_algo, struct_table + 1, sizeof(pqc_algo_t));
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_REQ_DIGITAL_SIGNATURE_ALGO:
        copy_mem (spdm_context->connection_info.algorithm.pqc_req_sig_algo, struct_table + 1, sizeof(pqc_algo_t));
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_KEY_ESTABLISHMENT_ALGO:
        copy_mem (spdm_context->connection_info.algorithm.pqc_kem_algo, struct_table + 1, sizeof(pqc_algo_t));
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_KEM_AUTH_ALGO:
        copy_mem (spdm_context->connection_info.algorithm.pqc_kem_auth_algo, struct_table + 1, sizeof(pqc_algo_t));
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_REQ_KEM_AUTH_ALGO:
        copy_mem (spdm_context->connection_info.algorithm.pqc_req_kem_auth_algo, struct_table + 1, sizeof(pqc_algo_t));
        break;
      default:
        ASSERT(FALSE);
        break;
      }
      fixed_alg_size = (struct_table->alg_count >> 4) & 0xF;
      ext_alg_count = struct_table->alg_count & 0xF;
      struct_table = (void *)((uintn)struct_table + sizeof (spdm_negotiate_algorithms_struct_table_t) + fixed_alg_size + sizeof(uint32) * ext_alg_count);
    }

    if (spdm_is_capabilities_flag_supported(spdm_context, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
      algo_size = spdm_get_pqc_sig_public_key_size (spdm_context->connection_info.algorithm.pqc_sig_algo);
      if (algo_size == 0) {
//        return RETURN_SECURITY_VIOLATION;
      }
      algo_size = spdm_get_pqc_sig_signature_size (spdm_context->connection_info.algorithm.pqc_sig_algo);
      if (algo_size == 0) {
//        return RETURN_SECURITY_VIOLATION;
      }
    }
    if (spdm_is_capabilities_flag_supported(spdm_context, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
      algo_size = spdm_get_dhe_pub_key_size (spdm_context->connection_info.algorithm.dhe_named_group);
      if (algo_size == 0) {
//        return RETURN_SECURITY_VIOLATION;
      }
      algo_size = spdm_get_pqc_kem_public_key_size (spdm_context->connection_info.algorithm.pqc_kem_algo);
      if (algo_size == 0) {
//        return RETURN_SECURITY_VIOLATION;
      }
      algo_size = spdm_get_pqc_kem_shared_key_size (spdm_context->connection_info.algorithm.pqc_kem_algo);
      if (algo_size == 0) {
//        return RETURN_SECURITY_VIOLATION;
      }
      algo_size = spdm_get_pqc_kem_cipher_text_size (spdm_context->connection_info.algorithm.pqc_kem_algo);
      if (algo_size == 0) {
//        return RETURN_SECURITY_VIOLATION;
      }
    }
    if (spdm_is_capabilities_flag_supported(spdm_context, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP) ||
        spdm_is_capabilities_flag_supported(spdm_context, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP)) {
      algo_size = spdm_get_aead_key_size (spdm_context->connection_info.algorithm.aead_cipher_suite);
      if (algo_size == 0) {
//        return RETURN_SECURITY_VIOLATION;
      }
    }
    if (spdm_is_capabilities_flag_supported(spdm_context, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
      algo_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg);
      if (algo_size == 0) {
//        return RETURN_SECURITY_VIOLATION;
      }
      algo_size = spdm_get_pqc_req_sig_public_key_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo);
      if (algo_size == 0) {
//        return RETURN_SECURITY_VIOLATION;
      }
      algo_size = spdm_get_pqc_req_sig_signature_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo);
      if (algo_size == 0) {
//        return RETURN_SECURITY_VIOLATION;
      }
    }
    if (spdm_is_capabilities_flag_supported(spdm_context, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ||
        spdm_is_capabilities_flag_supported(spdm_context, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
      if (spdm_context->connection_info.algorithm.key_schedule != SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
        return RETURN_SECURITY_VIOLATION;
      }
    }
  } else {
    spdm_context->connection_info.algorithm.dhe_named_group = 0;
    spdm_context->connection_info.algorithm.aead_cipher_suite = 0;
    spdm_context->connection_info.algorithm.req_base_asym_alg = 0;
    spdm_context->connection_info.algorithm.key_schedule = 0;
    zero_mem (spdm_context->connection_info.algorithm.pqc_sig_algo, sizeof(pqc_algo_t));
    zero_mem (spdm_context->connection_info.algorithm.pqc_req_sig_algo, sizeof(pqc_algo_t));
    zero_mem (spdm_context->connection_info.algorithm.pqc_kem_algo, sizeof(pqc_algo_t));
    zero_mem (spdm_context->connection_info.algorithm.pqc_kem_auth_algo, sizeof(pqc_algo_t));
    zero_mem (spdm_context->connection_info.algorithm.pqc_req_kem_auth_algo, sizeof(pqc_algo_t));
  }
  ASSERT (spdm_get_pqc_kem_public_key_size (spdm_context->connection_info.algorithm.pqc_kem_algo) <= MAX_PQC_KEM_PUBLIC_KEY_SIZE);
  ASSERT (spdm_get_pqc_kem_shared_key_size (spdm_context->connection_info.algorithm.pqc_kem_algo) <= MAX_PQC_KEM_SHARED_KEY_SIZE);
  ASSERT (spdm_get_pqc_kem_cipher_text_size (spdm_context->connection_info.algorithm.pqc_kem_algo) <= MAX_PQC_KEM_CIPHER_TEXT_SIZE);
  ASSERT (spdm_get_pqc_sig_public_key_size (spdm_context->connection_info.algorithm.pqc_sig_algo) <= MAX_PQC_SIG_PUBLIC_KEY_SIZE);
  ASSERT (spdm_get_pqc_sig_signature_size (spdm_context->connection_info.algorithm.pqc_sig_algo) <= MAX_PQC_SIG_SIGNATURE_SIZE);
  ASSERT (spdm_get_pqc_req_sig_public_key_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo) <= MAX_PQC_SIG_PUBLIC_KEY_SIZE);
  ASSERT (spdm_get_pqc_req_sig_signature_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo) <= MAX_PQC_SIG_SIGNATURE_SIZE);
  ASSERT (spdm_get_pqc_kem_public_key_size (spdm_context->connection_info.algorithm.pqc_kem_auth_algo) <= MAX_PQC_KEM_PUBLIC_KEY_SIZE);
  ASSERT (spdm_get_pqc_kem_shared_key_size (spdm_context->connection_info.algorithm.pqc_kem_auth_algo) <= MAX_PQC_KEM_SHARED_KEY_SIZE);
  ASSERT (spdm_get_pqc_kem_cipher_text_size (spdm_context->connection_info.algorithm.pqc_kem_auth_algo) <= MAX_PQC_KEM_CIPHER_TEXT_SIZE);
  ASSERT (spdm_get_pqc_kem_public_key_size (spdm_context->connection_info.algorithm.pqc_req_kem_auth_algo) <= MAX_PQC_KEM_PUBLIC_KEY_SIZE);
  ASSERT (spdm_get_pqc_kem_shared_key_size (spdm_context->connection_info.algorithm.pqc_req_kem_auth_algo) <= MAX_PQC_KEM_SHARED_KEY_SIZE);
  ASSERT (spdm_get_pqc_kem_cipher_text_size (spdm_context->connection_info.algorithm.pqc_req_kem_auth_algo) <= MAX_PQC_KEM_CIPHER_TEXT_SIZE);

  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  return RETURN_SUCCESS;
}

/**
  This function sends NEGOTIATE_ALGORITHMS and receives ALGORITHMS.

  @param  spdm_context                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The NEGOTIATE_ALGORITHMS is sent and the ALGORITHMS is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
return_status
spdm_negotiate_algorithms (
  IN     spdm_context_t  *spdm_context
  )
{
  uintn         retry;
  return_status status;

  retry = spdm_context->retry_times;
  do {
    status = try_spdm_negotiate_algorithms(spdm_context);
    if (RETURN_NO_RESPONSE != status) {
      return status;
    }
  } while (retry-- != 0);

  return status;
}

