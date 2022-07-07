/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_requester_emu.h"

static uint8  m_client_receive_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

extern void          *m_client_spdm_context;

void *
spdm_client_init (
  void
  );

boolean
communicate_platform_data (
  IN SOCKET           socket,
  IN uint32           command,
  IN uint8            *send_buffer,
  IN uintn            bytes_to_send,
  OUT uint32          *response,
  IN OUT uintn        *bytes_to_receive,
  OUT uint8           *receive_buffer
  );

return_status
do_measurement_via_spdm (
  IN uint32        *session_id
  );

return_status
do_authentication_via_spdm (
  void
  );

return_status
do_session_via_spdm (
  IN     boolean              use_psk
  );

doe_discovery_request_mine_t   m_doe_request = {
  {
    PCI_DOE_VENDOR_ID_PCISIG,
    PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY,
    0,
    sizeof(m_doe_request) / sizeof(uint32), // length
  },
  {
    0, // index
  },
};

boolean
platform_client_routine (
  void
  )
{
  boolean        result;
  uint32         response;
  uintn          response_size;
  return_status  status;

  response_size = sizeof(m_client_receive_buffer);
  result = communicate_platform_data (
             0,
             SOCKET_SPDM_COMMAND_TEST,
             (uint8 *)"Client Hello!",
             sizeof("Client Hello!"),
             &response,
             &response_size,
             m_client_receive_buffer
             );
  if (!result) {
    goto done;
  }

  if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
    doe_discovery_response_mine_t  doe_response;

    do {
      response_size = sizeof(doe_response);
      result = communicate_platform_data (
                0,
                SOCKET_SPDM_COMMAND_NORMAL,
                (uint8 *)&m_doe_request,
                sizeof(m_doe_request),
                &response,
                &response_size,
                (uint8 *)&doe_response
                );
      if (!result) {
        goto done;
      }
      ASSERT (response_size == sizeof(doe_response));
      ASSERT (doe_response.doe_header.vendor_id == PCI_DOE_VENDOR_ID_PCISIG);
      ASSERT (doe_response.doe_header.data_object_type == PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY);
      ASSERT (doe_response.doe_header.length == sizeof(doe_response) / sizeof(uint32));
      ASSERT (doe_response.doe_discovery_response.vendor_id == PCI_DOE_VENDOR_ID_PCISIG);

      m_doe_request.doe_discovery_request.index = doe_response.doe_discovery_response.next_index;
    } while (doe_response.doe_discovery_response.next_index != 0);
  }

  m_client_spdm_context = spdm_client_init ();
  if (m_client_spdm_context == NULL) {
    goto done;
  }

  // Do test - begin
perf_start (PERF_ID_REQUESTER);
  status = do_authentication_via_spdm ();
  if (RETURN_ERROR(status)) {
    printf ("do_authentication_via_spdm - %x\n", (uint32)status);
    goto done;
  }

  if ((m_exe_connection & EXE_CONNECTION_MEAS) != 0) {
    status = do_measurement_via_spdm (NULL);
    if (RETURN_ERROR(status)) {
      printf ("do_measurement_via_spdm - %x\n", (uint32)status);
      goto done;
    }
  }

  if (m_use_version >= SPDM_MESSAGE_VERSION_11) {
    if ((m_exe_session & EXE_SESSION_KEY_EX) != 0) {
      status = do_session_via_spdm (FALSE);
      if (RETURN_ERROR(status)) {
        printf ("do_session_via_spdm - %x\n", (uint32)status);
        goto done;
      }
    }

    if ((m_exe_session & EXE_SESSION_PSK) != 0) {
      status = do_session_via_spdm (TRUE);
      if (RETURN_ERROR(status)) {
        printf ("do_session_via_spdm - %x\n", (uint32)status);
        goto done;
      }
    }
  }
perf_stop (PERF_ID_REQUESTER);
  // Do test - end

done:
  response_size = 0;
  result = communicate_platform_data (
            0,
            SOCKET_SPDM_COMMAND_SHUTDOWN - m_exe_mode,
            NULL,
            0,
            &response,
            &response_size,
            NULL
            );

  if (m_client_spdm_context != NULL) {
    free (m_client_spdm_context);
  }

  return TRUE;
}
