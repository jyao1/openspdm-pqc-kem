/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_responder_emu.h"

uint32 m_server_command;
uintn  m_server_receive_buffer_size;
uint8  m_server_receive_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

extern void *m_server_spdm_context;

doe_discovery_response_mine_t   m_doe_response = {
  {
    PCI_DOE_VENDOR_ID_PCISIG,
    PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY,
    0,
    sizeof(m_doe_response) / sizeof(uint32), // length
  },
  {
    PCI_DOE_VENDOR_ID_PCISIG,
    PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY,
    0x00
  },
};

boolean
platform_server (
  void
  )
{
  boolean            result;
  return_status      status;

  if (TRUE) {
    status = spdm_responder_dispatch_message (m_server_spdm_context);
    if (status == RETURN_SUCCESS) {
      // success dispatch SPDM message
    }
    if (status == RETURN_DEVICE_ERROR) {
      printf ("Server Critical Error - STOP\n");
      return FALSE;
    }
    if (status != RETURN_UNSUPPORTED) {
      return TRUE;
    }
    switch(m_server_command) {
    case SOCKET_SPDM_COMMAND_TEST:
      result = send_platform_data (
                 0,
                 SOCKET_SPDM_COMMAND_TEST,
                 (uint8 *)"Server Hello!",
                 sizeof("Server Hello!")
                 );
      if (!result) {
        printf ("send_platform_data Error - %x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
        return TRUE;
      }
      break;

    case SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE:
      spdm_init_key_update_encap_state (m_server_spdm_context);
      result = send_platform_data (0, SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE, NULL, 0);
      if (!result) {
        printf ("send_platform_data Error - %x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
        return TRUE;
      }
      break;

    case SOCKET_SPDM_COMMAND_SHUTDOWN:
      result = send_platform_data (0, SOCKET_SPDM_COMMAND_SHUTDOWN, NULL, 0);
      if (!result) {
        printf ("send_platform_data Error - %x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
        return TRUE;
      }
      return FALSE;
      break;

    case SOCKET_SPDM_COMMAND_CONTINUE:
      result = send_platform_data (0, SOCKET_SPDM_COMMAND_CONTINUE, NULL, 0);
      if (!result) {
        printf ("send_platform_data Error - %x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
        return TRUE;
      }
      return TRUE;
      break;

    case SOCKET_SPDM_COMMAND_NORMAL:
      if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        doe_discovery_request_mine_t  *doe_request;

        doe_request = (void *)m_server_receive_buffer;
        if ((doe_request->doe_header.vendor_id != PCI_DOE_VENDOR_ID_PCISIG) ||
            (doe_request->doe_header.data_object_type != PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY)) {
          // unknown message
          return TRUE;
        }
        ASSERT (m_server_receive_buffer_size == sizeof(doe_discovery_request_mine_t));
        ASSERT (doe_request->doe_header.length == sizeof(*doe_request) / sizeof(uint32));

        switch (doe_request->doe_discovery_request.index) {
        case 0:
          m_doe_response.doe_discovery_response.data_object_type = PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY;
          m_doe_response.doe_discovery_response.next_index = 1;
          break;
        case 1:
          m_doe_response.doe_discovery_response.data_object_type = PCI_DOE_DATA_OBJECT_TYPE_SPDM;
          m_doe_response.doe_discovery_response.next_index = 2;
          break;
        case 2:
        default:
          m_doe_response.doe_discovery_response.data_object_type = PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM;
          m_doe_response.doe_discovery_response.next_index = 0;
          break;
        }

        result = send_platform_data (
                  0,
                  SOCKET_SPDM_COMMAND_NORMAL,
                  (uint8 *)&m_doe_response,
                  sizeof(m_doe_response)
                  );
        if (!result) {
          printf ("send_platform_data Error - %x\n",
  #ifdef _MSC_VER
            WSAGetLastError()
  #else
            errno
  #endif
            );
          return TRUE;
        }
      } else {
        // unknown message
        return TRUE;
      }
      break;

    default:
      printf ("Unrecognized platform interface command %x\n", m_server_command);
      result = send_platform_data (0, SOCKET_SPDM_COMMAND_UNKOWN, NULL, 0);
      if (!result) {
        printf ("send_platform_data Error - %x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
        return TRUE;
      }
      return TRUE;
    }
  }
  return TRUE;
}
