/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_requester_emu.h"

extern void          *m_client_spdm_context;

/**
  This function sends GET_DIGEST, GET_CERTIFICATE, CHALLENGE
  to authenticate the device.

  This function is combination of spdm_get_digest, spdm_get_certificate, spdm_challenge.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  slot_mask                     The slots which deploy the CertificateChain.
  @param  total_digest_buffer            A pointer to a destination buffer to store the digest buffer.
  @param  slot_id                      The number of slot for the certificate chain.
  @param  cert_chain_size                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  cert_chain                    A pointer to a destination buffer to store the certificate chain.
  @param  measurement_hash_type          The type of the measurement hash.
  @param  measurement_hash              A pointer to a destination buffer to store the measurement hash.

  @retval RETURN_SUCCESS               The authentication is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
return_status
spdm_authentication (
  IN     void                 *context,
     OUT uint8                *slot_mask,
     OUT void                 *total_digest_buffer,
  IN     uint8                slot_id,
  IN OUT uintn                *cert_chain_size,
     OUT void                 *cert_chain,
  IN     uint8                measurement_hash_type,
     OUT void                 *measurement_hash
  )
{
  return_status         status;

  if ((m_exe_connection & EXE_CONNECTION_DIGEST) != 0) {
    if (slot_id != 0xFF) {
      status = spdm_get_digest (context, slot_mask, total_digest_buffer);
      if (RETURN_ERROR(status)) {
        return status;
      }
    }
  }

  if ((m_exe_connection & EXE_CONNECTION_CERT) != 0) {
    if (slot_id != 0xFF) {
      status = spdm_get_certificate (context, slot_id, cert_chain_size, cert_chain);
      if (RETURN_ERROR(status)) {
        return status;
      }
    }
  }

  if ((m_exe_connection & EXE_CONNECTION_CHAL) != 0) {
    status = spdm_challenge (context, slot_id, measurement_hash_type, measurement_hash);
    if (RETURN_ERROR(status)) {
      return status;
    }
  }
  return RETURN_SUCCESS;
}

/**
  This function executes SPDM authentication.
  
  @param[in]  spdm_context            The SPDM context for the device.
**/
return_status
do_authentication_via_spdm (
  void
  )
{
  return_status         status;
  void                  *spdm_context;
  uint8                 slot_mask;
  uint8                 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];
  uint8                 measurement_hash[MAX_HASH_SIZE];
  uintn                 cert_chain_size;
  uint8                 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];

  spdm_context = m_client_spdm_context;

  zero_mem (total_digest_buffer, sizeof(total_digest_buffer));
  cert_chain_size = sizeof(cert_chain);
  zero_mem (cert_chain, sizeof(cert_chain));
  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_authentication (
             spdm_context,
             &slot_mask,
             &total_digest_buffer,
             m_use_slot_id,
             &cert_chain_size,
             cert_chain,
             m_use_measurement_summary_hash_type,
             measurement_hash
             );
  if (RETURN_ERROR(status)) {
    return status;
  }
  return RETURN_SUCCESS;
}
