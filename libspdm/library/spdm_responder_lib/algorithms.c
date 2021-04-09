/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_responder_lib_internal.h"

#pragma pack(1)
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
  spdm_negotiate_algorithms_common_struct_table_t  struct_table[4];
  spdm_negotiate_algorithms_pqc_struct_table_t     pqc_struct_table[3];
} spdm_algorithms_response_mine_t;
#pragma pack()

uint32 m_hash_priority_table[] = {
#if OPENSPDM_SHA256_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
#endif
#if OPENSPDM_SHA384_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
#endif
#if OPENSPDM_SHA256_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
#endif
};

uint32 m_asym_priority_table[] = {
#if OPENSPDM_ECDSA_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
#endif
#if OPENSPDM_RSA_PSS_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
#endif
#if OPENSPDM_RSA_SSA_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
#endif
};

uint32 m_req_asym_priority_table[] = {
#if OPENSPDM_RSA_PSS_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
#endif
#if OPENSPDM_RSA_SSA_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
#endif
#if OPENSPDM_ECDSA_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
#endif
};

uint32 m_dhe_priority_table[] = {
#if OPENSPDM_ECDHE_SUPPORT == 1
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1,
#endif
#if OPENSPDM_FFDHE_SUPPORT == 1
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,
#endif
};

uint32 m_aead_priority_table[] = {
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,
  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,
#endif
#if OPENSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,
#endif
};

uint32 m_key_schedule_priority_table[] = {
  SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH,
};

uint32 m_measurement_hash_priority_table[] = {
#if OPENSPDM_SHA256_SUPPORT == 1
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,
#endif
#if OPENSPDM_SHA384_SUPPORT == 1
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
#endif
#if OPENSPDM_SHA256_SUPPORT == 1
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
#endif
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,
};

uint32 m_measurement_spec_priority_table[] = {
  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};

/**
  Select the preferred supproted algorithm according to the priority_table.

  @param  priority_table                The priority table.
  @param  priority_table_count           The count of the priroty table entry.
  @param  local_algo                    Local supported algorithm.
  @param  peer_algo                     Peer supported algorithm.

  @return final preferred supported algorithm
**/
uint32
spdm_prioritize_algorithm (
  IN uint32            *priority_table,
  IN uintn             priority_table_count,
  IN uint32            local_algo,
  IN uint32            peer_algo
  )
{
  uint32 common_algo;
  uintn  index;

  common_algo = (local_algo & peer_algo);
  for (index = 0; index < priority_table_count; index++) {
    if ((common_algo & priority_table[index]) != 0) {
      return priority_table[index];
    }
  }

  return 0;
}

pqc_algo_t m_pqc_sig_priority_table[] = {
//{SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_2},
//{0, 0, 0, 0, 0, 0, 0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHAKE256_128F_ROBUST >> 24},
//{0, 0, 0, 0, 0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_SHA256_128F_ROBUST >> 8},
//{0, 0, 0, 0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_128F_ROBUST},
  {0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_FALCON_512},
  {0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_FALCON_1024},
//{0, 0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_I_CLASSIC},
//{0, 0, 0, 0, 0, 0, 0, 0, 0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L1_FS},
};

pqc_algo_t m_pqc_req_sig_priority_table[] = {
//{SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_DILITHIUM_2},
  {0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_FALCON_512},
  {0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_FALCON_1024},
//{0, 0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_RAINBOW_I_CLASSIC},
//{0, 0, 0, 0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_SPHINCS_HARAKA_128F_ROBUST},
//{0, 0, 0, 0, 0, 0, 0, 0, 0, SPDM_ALGORITHMS_PQC_DIGITAL_SIGNATURE_ALGO_PICNIC_L1_FS},
};

pqc_algo_t m_pqc_kem_priority_table[] = {
//{SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_BIKE1_L1_CPA},
  {0, 0, 0, 0, 0, 0, 0, 0, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_FRODOKEM_640_AES},
  {0, 0, 0, 0, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_KYBER_512},
//{0, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_CLASSIC_MCELIECE_348864},
//{0, 0, 0, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_HQC_128},
//{0, 0, 0, 0, 0, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRU_HPS_2048_509},
//{0, 0, 0, 0, 0, 0, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_NTRULPR653},
//{0, 0, 0, 0, 0, 0, 0, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_LIGHTSABER_KEM},
//{0, 0, 0, 0, 0, 0, 0, 0, 0, SPDM_ALGORITHMS_PQC_KEY_ESTABLISHMENT_ALGO_SIDH_P434},
};

/**
  Select the preferred supproted algorithm according to the priority_table.

  @param  priority_table                The priority table.
  @param  priority_table_count           The count of the priroty table entry.
  @param  local_algo                    Local supported algorithm.
  @param  peer_algo                     Peer supported algorithm.

  @return final preferred supported algorithm
**/
void
spdm_pqc_prioritize_algorithm (
  IN pqc_algo_t            *pqc_priority_table,
  IN uintn             pqc_priority_table_count,
  IN pqc_algo_t        local_pqc_algo,
  IN pqc_algo_t        peer_pqc_algo,
  OUT pqc_algo_t       final_pqc_algo
  )
{
  pqc_algo_t common_pqc_algo;
  uintn      index;
  uintn      index_j;

  spdm_pqc_algo_and (local_pqc_algo, peer_pqc_algo, common_pqc_algo);
  if (spdm_pqc_algo_is_zero (common_pqc_algo)) {
    zero_mem (final_pqc_algo, sizeof(pqc_algo_t));
    return ;
  }

  for (index = 0; index < pqc_priority_table_count; index++) {
    spdm_pqc_algo_and (common_pqc_algo, pqc_priority_table[index], final_pqc_algo);
    if (!spdm_pqc_algo_is_zero (final_pqc_algo)) {
      return ;
    }
  }

  //
  // Not found in priority table, just return first bit.
  //
  zero_mem (final_pqc_algo, sizeof(pqc_algo_t));
  for (index = 0; index < sizeof(pqc_algo_t); index++) {
    if (common_pqc_algo[index] != 0) {
      for (index_j = 0; index_j < 8; index_j++) {
        if ((common_pqc_algo[index] & (1 << index_j)) != 0) {
          final_pqc_algo[index] = (1 << index_j);
          return ;
        }
      }
    }
  }

  return ;
}

/**
  Process the SPDM NEGOTIATE_ALGORITHMS request and return the response.

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
spdm_get_response_algorithms (
  IN     void                 *context,
  IN     uintn                request_size,
  IN     void                 *request,
  IN OUT uintn                *response_size,
     OUT void                 *response
  )
{
  spdm_negotiate_algorithms_request_t              *spdm_request;
  uintn                                          spdm_request_size;
  spdm_algorithms_response_mine_t                  *spdm_response;
  spdm_negotiate_algorithms_struct_table_t  *struct_table;
  uintn                                          index;
  spdm_context_t                            *spdm_context;
  return_status                                  status;
  uint32                                         algo_size;
  uint8                                          fixed_alg_size;
  uint8                                          ext_alg_count;

  spdm_context = context;
  spdm_request = request;

  if (spdm_context->response_state != SPDM_RESPONSE_STATE_NORMAL) {
    return spdm_responder_handle_response_state(spdm_context, spdm_request->header.request_response_code, response_size, response);
  }
  if (spdm_context->connection_info.connection_state != SPDM_CONNECTION_STATE_AFTER_CAPABILITIES) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }

  if (request_size < sizeof(spdm_negotiate_algorithms_request_t)) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
  if (request_size < sizeof(spdm_negotiate_algorithms_request_t) + 
                    sizeof(uint32) * spdm_request->ext_asym_count +
                    sizeof(uint32) * spdm_request->ext_hash_count +
                    sizeof(spdm_negotiate_algorithms_struct_table_t) * spdm_request->header.param1) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
  struct_table = (void *)((uintn)spdm_request +
                            sizeof(spdm_negotiate_algorithms_request_t) +
                            sizeof(uint32) * spdm_request->ext_asym_count +
                            sizeof(uint32) * spdm_request->ext_hash_count
                            );
  if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
    for (index = 0; index < spdm_request->header.param1; index++) {
      if ((uintn)spdm_request + request_size < (uintn)struct_table) {
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
      fixed_alg_size = (struct_table->alg_count >> 4) & 0xF;
      ext_alg_count = struct_table->alg_count & 0xF;
      if ((uintn)spdm_request + request_size - (uintn)struct_table < sizeof(spdm_negotiate_algorithms_struct_table_t) + fixed_alg_size) {
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
      if (fixed_alg_size == 2) {
        switch (struct_table->alg_type) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
          break;
        default:
          spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
          return RETURN_SUCCESS;
        }
      } else if (fixed_alg_size == sizeof(pqc_algo_t)) {
        switch (struct_table->alg_type) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_DIGITAL_SIGNATURE_ALGO:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_REQ_DIGITAL_SIGNATURE_ALGO:
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_KEY_ESTABLISHMENT_ALGO:
          break;
        default:
          spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
          return RETURN_SUCCESS;
        }
      } else {
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
      if ((uintn)spdm_request + request_size - (uintn)struct_table - sizeof(spdm_negotiate_algorithms_struct_table_t) + fixed_alg_size < sizeof(uint32) * ext_alg_count) {
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
      struct_table = (void *)((uintn)struct_table + sizeof (spdm_negotiate_algorithms_struct_table_t) + fixed_alg_size + sizeof(uint32) * ext_alg_count);
    }
  }
  request_size = (uintn)struct_table - (uintn)spdm_request;
  if (request_size != spdm_request->length) {
    return RETURN_DEVICE_ERROR;
  }
  spdm_request_size = request_size;

  //
  // Cache
  //
  status = spdm_append_message_a (spdm_context, spdm_request, spdm_request_size);
  if (RETURN_ERROR(status)) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }

  ASSERT (*response_size >= sizeof(spdm_algorithms_response_mine_t));
  *response_size = sizeof(spdm_algorithms_response_mine_t);
  zero_mem (response, *response_size);
  spdm_response = response;

  if (spdm_is_version_supported (spdm_context, SPDM_MESSAGE_VERSION_11)) {
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.param1 = 4 + 3; // Number of Algorithms Structure Tables
  } else {
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.param1 = 0;
    *response_size = sizeof(spdm_algorithms_response_mine_t) - sizeof(spdm_negotiate_algorithms_common_struct_table_t) * 4
                     - sizeof(spdm_negotiate_algorithms_pqc_struct_table_t) * 3;
  }
  spdm_response->header.request_response_code = SPDM_ALGORITHMS;
  spdm_response->header.param2 = 0;
  spdm_response->length = (uint16)*response_size;

  spdm_context->connection_info.algorithm.measurement_spec = spdm_request->measurement_specification;
  spdm_context->connection_info.algorithm.measurement_hash_algo = spdm_context->local_context.algorithm.measurement_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = spdm_request->base_asym_algo;
  spdm_context->connection_info.algorithm.bash_hash_algo = spdm_request->bash_hash_algo;
  if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
    struct_table = (void *)((uintn)spdm_request +
                            sizeof(spdm_negotiate_algorithms_request_t) +
                            sizeof(uint32) * spdm_request->ext_asym_count +
                            sizeof(uint32) * spdm_request->ext_hash_count
                            );
    for (index = 0; index < spdm_request->header.param1; index++) {
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
      }
      fixed_alg_size = (struct_table->alg_count >> 4) & 0xF;
      ext_alg_count = struct_table->alg_count & 0xF;
      struct_table = (void *)((uintn)struct_table + sizeof (spdm_negotiate_algorithms_struct_table_t) + fixed_alg_size + sizeof(uint32) * ext_alg_count);
    }
  }

  spdm_response->measurement_specification_sel = (uint8)spdm_prioritize_algorithm (
                                                m_measurement_spec_priority_table,
                                                ARRAY_SIZE(m_measurement_spec_priority_table),
                                                spdm_context->local_context.algorithm.measurement_spec,
                                                spdm_context->connection_info.algorithm.measurement_spec
                                                );
  spdm_response->measurement_hash_algo = spdm_prioritize_algorithm (
                                        m_measurement_hash_priority_table,
                                        ARRAY_SIZE(m_measurement_hash_priority_table),
                                        spdm_context->local_context.algorithm.measurement_hash_algo,
                                        spdm_context->connection_info.algorithm.measurement_hash_algo
                                        );
  spdm_response->base_asym_sel = spdm_prioritize_algorithm (
                                m_asym_priority_table,
                                ARRAY_SIZE(m_asym_priority_table),
                                spdm_context->local_context.algorithm.base_asym_algo,
                                spdm_context->connection_info.algorithm.base_asym_algo
                                );
  spdm_response->base_hash_sel = spdm_prioritize_algorithm (
                                m_hash_priority_table,
                                ARRAY_SIZE(m_hash_priority_table),
                                spdm_context->local_context.algorithm.bash_hash_algo,
                                spdm_context->connection_info.algorithm.bash_hash_algo
                                );
  spdm_response->struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
  spdm_response->struct_table[0].alg_count = 0x20;
  spdm_response->struct_table[0].alg_supported = (uint16)spdm_prioritize_algorithm (
                                                m_dhe_priority_table,
                                                ARRAY_SIZE(m_dhe_priority_table),
                                                spdm_context->local_context.algorithm.dhe_named_group,
                                                spdm_context->connection_info.algorithm.dhe_named_group
                                                );
  spdm_response->struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
  spdm_response->struct_table[1].alg_count = 0x20;
  spdm_response->struct_table[1].alg_supported = (uint16)spdm_prioritize_algorithm (
                                                m_aead_priority_table,
                                                ARRAY_SIZE(m_aead_priority_table),
                                                spdm_context->local_context.algorithm.aead_cipher_suite,
                                                spdm_context->connection_info.algorithm.aead_cipher_suite
                                                );
  spdm_response->struct_table[2].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
  spdm_response->struct_table[2].alg_count = 0x20;
  spdm_response->struct_table[2].alg_supported = (uint16)spdm_prioritize_algorithm (
                                                m_req_asym_priority_table,
                                                ARRAY_SIZE(m_req_asym_priority_table),
                                                spdm_context->local_context.algorithm.req_base_asym_alg,
                                                spdm_context->connection_info.algorithm.req_base_asym_alg
                                                );
  spdm_response->struct_table[3].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
  spdm_response->struct_table[3].alg_count = 0x20;
  spdm_response->struct_table[3].alg_supported = (uint16)spdm_prioritize_algorithm (
                                                m_key_schedule_priority_table,
                                                ARRAY_SIZE(m_key_schedule_priority_table),
                                                spdm_context->local_context.algorithm.key_schedule,
                                                spdm_context->connection_info.algorithm.key_schedule
                                                );
  spdm_response->pqc_struct_table[0].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_DIGITAL_SIGNATURE_ALGO;
  spdm_response->pqc_struct_table[0].alg_count = (uint8)(sizeof(pqc_algo_t) << 4);
  spdm_pqc_prioritize_algorithm (
    m_pqc_sig_priority_table,
    ARRAY_SIZE(m_pqc_sig_priority_table),
    spdm_context->local_context.algorithm.pqc_sig_algo,
    spdm_context->connection_info.algorithm.pqc_sig_algo,
    spdm_response->pqc_struct_table[0].alg_supported
    );
  spdm_response->pqc_struct_table[1].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_REQ_DIGITAL_SIGNATURE_ALGO;
  spdm_response->pqc_struct_table[1].alg_count = (uint8)(sizeof(pqc_algo_t) << 4);
  spdm_pqc_prioritize_algorithm (
    m_pqc_req_sig_priority_table,
    ARRAY_SIZE(m_pqc_req_sig_priority_table),
    spdm_context->local_context.algorithm.pqc_req_sig_algo,
    spdm_context->connection_info.algorithm.pqc_req_sig_algo,
    spdm_response->pqc_struct_table[1].alg_supported
    );
  spdm_response->pqc_struct_table[2].alg_type = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_PQC_KEY_ESTABLISHMENT_ALGO;
  spdm_response->pqc_struct_table[2].alg_count = (uint8)(sizeof(pqc_algo_t) << 4);
  spdm_pqc_prioritize_algorithm (
    m_pqc_kem_priority_table,
    ARRAY_SIZE(m_pqc_kem_priority_table),
    spdm_context->local_context.algorithm.pqc_kem_algo,
    spdm_context->connection_info.algorithm.pqc_kem_algo,
    spdm_response->pqc_struct_table[2].alg_supported
    );

  //
  // Cache
  //
  status = spdm_append_message_a (spdm_context, spdm_response, *response_size);
  if (RETURN_ERROR(status)) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }

  spdm_context->connection_info.algorithm.measurement_spec = spdm_response->measurement_specification_sel;
  spdm_context->connection_info.algorithm.measurement_hash_algo = spdm_response->measurement_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = spdm_response->base_asym_sel;
  spdm_context->connection_info.algorithm.bash_hash_algo = spdm_response->base_hash_sel;

  if (spdm_is_capabilities_flag_supported(spdm_context, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
    if (spdm_context->connection_info.algorithm.measurement_spec != SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
      spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
      return RETURN_SUCCESS;
    }
    algo_size = spdm_get_measurement_hash_size (spdm_context->connection_info.algorithm.measurement_hash_algo);
    if (algo_size == 0) {
      spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
      return RETURN_SUCCESS;
    }
  }
  algo_size = spdm_get_hash_size (spdm_context->connection_info.algorithm.bash_hash_algo);
  if (algo_size == 0) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
  if (spdm_is_capabilities_flag_supported(spdm_context, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
    algo_size = spdm_get_asym_signature_size (spdm_context->connection_info.algorithm.base_asym_algo);
    if (algo_size == 0) {
      spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
      return RETURN_SUCCESS;
    }
  }

  if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
    spdm_context->connection_info.algorithm.dhe_named_group = spdm_response->struct_table[0].alg_supported;
    spdm_context->connection_info.algorithm.aead_cipher_suite = spdm_response->struct_table[1].alg_supported;
    spdm_context->connection_info.algorithm.req_base_asym_alg = spdm_response->struct_table[2].alg_supported;
    spdm_context->connection_info.algorithm.key_schedule = spdm_response->struct_table[3].alg_supported;
    copy_mem (spdm_context->connection_info.algorithm.pqc_sig_algo, spdm_response->pqc_struct_table[0].alg_supported, sizeof(pqc_algo_t));
    copy_mem (spdm_context->connection_info.algorithm.pqc_req_sig_algo, spdm_response->pqc_struct_table[1].alg_supported, sizeof(pqc_algo_t));
    copy_mem (spdm_context->connection_info.algorithm.pqc_kem_algo, spdm_response->pqc_struct_table[2].alg_supported, sizeof(pqc_algo_t));

    if (spdm_is_capabilities_flag_supported(spdm_context, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
      algo_size = spdm_get_pqc_sig_public_key_size (spdm_context->connection_info.algorithm.pqc_sig_algo);
      if (algo_size == 0) {
        DEBUG ((DEBUG_INFO, "Unsupported PQC SIG!\n"));
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
      algo_size = spdm_get_pqc_sig_signature_size (spdm_context->connection_info.algorithm.pqc_sig_algo);
      if (algo_size == 0) {
        DEBUG ((DEBUG_INFO, "Unsupported PQC SIG!\n"));
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
    }

    if (spdm_is_capabilities_flag_supported(spdm_context, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
      algo_size = spdm_get_dhe_pub_key_size (spdm_context->connection_info.algorithm.dhe_named_group);
      if (algo_size == 0) {
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
      algo_size = spdm_get_pqc_kem_public_key_size (spdm_context->connection_info.algorithm.pqc_kem_algo);
      if (algo_size == 0) {
        DEBUG ((DEBUG_INFO, "Unsupported PQC KEM!\n"));
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
      algo_size = spdm_get_pqc_kem_shared_key_size (spdm_context->connection_info.algorithm.pqc_kem_algo);
      if (algo_size == 0) {
        DEBUG ((DEBUG_INFO, "Unsupported PQC KEM!\n"));
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
      algo_size = spdm_get_pqc_kem_cipher_text_size (spdm_context->connection_info.algorithm.pqc_kem_algo);
      if (algo_size == 0) {
        DEBUG ((DEBUG_INFO, "Unsupported PQC KEM!\n"));
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
    }
    if (spdm_is_capabilities_flag_supported(spdm_context, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP) ||
        spdm_is_capabilities_flag_supported(spdm_context, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP)) {
      algo_size = spdm_get_aead_key_size (spdm_context->connection_info.algorithm.aead_cipher_suite);
      if (algo_size == 0) {
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
    }
    if (spdm_is_capabilities_flag_supported(spdm_context, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
      algo_size = spdm_get_req_asym_signature_size (spdm_context->connection_info.algorithm.req_base_asym_alg);
      if (algo_size == 0) {
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
      algo_size = spdm_get_pqc_req_sig_public_key_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo);
      if (algo_size == 0) {
        DEBUG ((DEBUG_INFO, "Unsupported PQC req SIG!\n"));
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
      algo_size = spdm_get_pqc_req_sig_signature_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo);
      if (algo_size == 0) {
        DEBUG ((DEBUG_INFO, "Unsupported PQC req SIG!\n"));
        spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
        return RETURN_SUCCESS;
      }
    }
    if (spdm_is_capabilities_flag_supported(spdm_context, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ||
        spdm_is_capabilities_flag_supported(spdm_context, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
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
  }
  ASSERT (spdm_get_pqc_kem_public_key_size (spdm_context->connection_info.algorithm.pqc_kem_algo) <= MAX_PQC_KEM_PUBLIC_KEY_SIZE);
  ASSERT (spdm_get_pqc_kem_shared_key_size (spdm_context->connection_info.algorithm.pqc_kem_algo) <= MAX_PQC_KEM_SHARED_KEY_SIZE);
  ASSERT (spdm_get_pqc_kem_cipher_text_size (spdm_context->connection_info.algorithm.pqc_kem_algo) <= MAX_PQC_KEM_CIPHER_TEXT_SIZE);
  ASSERT (spdm_get_pqc_sig_public_key_size (spdm_context->connection_info.algorithm.pqc_sig_algo) <= MAX_PQC_SIG_PUBLIC_KEY_SIZE);
  ASSERT (spdm_get_pqc_sig_signature_size (spdm_context->connection_info.algorithm.pqc_sig_algo) <= MAX_PQC_SIG_SIGNATURE_SIZE);
  ASSERT (spdm_get_pqc_req_sig_public_key_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo) <= MAX_PQC_SIG_PUBLIC_KEY_SIZE);
  ASSERT (spdm_get_pqc_req_sig_signature_size (spdm_context->connection_info.algorithm.pqc_req_sig_algo) <= MAX_PQC_SIG_SIGNATURE_SIZE);

  spdm_set_connection_state (spdm_context, SPDM_CONNECTION_STATE_NEGOTIATED);

  return RETURN_SUCCESS;
}

