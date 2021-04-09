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
  // param1 == attributes
  // param2 == request ID
  uint32                 sequence_id;
  uint32                 offset;
  uint32                 length;
  uint8                  data[MAX_SPDM_FRAGMENT_LENGTH];
} my_spdm_fragment_request_t;

typedef struct {
  spdm_message_header_t  header;
  // param1 == attributes
  // param2 == response ID
  uint32                 sequence_id;
  uint32                 offset;
  uint32                 length;
  uint8                  data[MAX_SPDM_FRAGMENT_LENGTH];
} my_spdm_fragment_response_t;

#pragma pack()

/**
  Send an SPDM FRAGMENT request to a device.

  @param  spdm_context                  The SPDM context for the device.
  @param  session_id                    Indicate if the request is a secured message.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  request_size                  size in bytes of the request data buffer.
  @param  request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.

  @retval RETURN_SUCCESS               The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM request is sent to the device.
**/
return_status
spdm_send_spdm_fragment_encap_request (
  IN     spdm_context_t  *spdm_context,
  IN     uint32               *session_id,
  IN     uintn                request_size,
  IN     void                 *request
  )
{
  my_spdm_fragment_request_t  my_request;
  uintn                       my_request_size;
  uint32                      offset;
  uint32                      length;
  uint8                       request_id;
  uint32                      sequence_id;
  return_status               status;
  spdm_fragment_request_ack_t my_response;
  uintn                       my_response_size;

  ASSERT (request_size <= (uint32)-1);

  request_id = 0x7f;

  sequence_id = 0;
  offset = 0;
  while (offset < request_size) {
    length = MAX_SPDM_FRAGMENT_LENGTH;
    if (length > request_size - offset) {
      length = (uint32)(request_size - offset);
    }

    my_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    my_request.header.request_response_code = SPDM_FRAGMENT_REQUEST;
    my_request.header.param1 = 0;
    if (offset == 0) {
      my_request.header.param1 |= SPDM_FRAGMENT_REQUEST_ATTRIBUTER_BEGIN;
    }
    if (offset + length == request_size) {
      my_request.header.param1 |= SPDM_FRAGMENT_REQUEST_ATTRIBUTER_END;
    }
    my_request.header.param2 = request_id;

    my_request.sequence_id = sequence_id;
    my_request.offset = offset;
    my_request.length = length;
    copy_mem (my_request.data, (uint8 *)request + offset, length);
    my_request_size = sizeof(spdm_fragment_request_t) + length;

    status = spdm_send_spdm_request (spdm_context, session_id, my_request_size, &my_request);
    if (RETURN_ERROR(status)) {
      return RETURN_DEVICE_ERROR;
    }

    if ((my_request.header.param1 & SPDM_FRAGMENT_REQUEST_ATTRIBUTER_END) != 0) {
      break;
    }

    my_response_size = sizeof(my_response);
    zero_mem (&my_response, sizeof(my_response));
    status = spdm_receive_spdm_response (spdm_context, NULL, &my_response_size, &my_response);
    if (RETURN_ERROR(status)) {
      return RETURN_DEVICE_ERROR;
    }
    if (my_response_size < sizeof(spdm_message_header_t)) {
      return RETURN_DEVICE_ERROR;
    }

    if (my_response.header.request_response_code != SPDM_FRAGMENT_REQUEST_ACK) {
      return RETURN_SUCCESS;
    }
    if (my_response_size != sizeof(spdm_fragment_request_ack_t)) {
      return RETURN_DEVICE_ERROR;
    }
    if (my_response.header.param2 != my_request.header.param2) {
      return RETURN_DEVICE_ERROR;
    }
    if (my_response.sequence_id != my_request.sequence_id) {
      return RETURN_DEVICE_ERROR;
    }

    sequence_id ++;
    offset += length;
  }

  return RETURN_SUCCESS;
}


/**
  Receive an SPDM FRAGMENT response from a device.

  @param  spdm_context                  The SPDM context for the device.
  @param  session_id                    Indicate if the response is a secured message.
                                       If session_id is NULL, it is a normal message.
                                       If session_id is NOT NULL, it is a secured message.
  @param  response_size                 size in bytes of the response data buffer.
  @param  response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.

  @retval RETURN_SUCCESS               The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is received from the device.
**/
return_status
spdm_receive_spdm_fragment_encap_response (
  IN     spdm_context_t  *spdm_context,
  IN     uint32               *session_id,
  IN OUT uintn                *response_size,
     OUT void                 *response
  )
{
  my_spdm_fragment_response_t  my_response;
  uintn                        my_response_size;
  return_status                status;
  uintn                        received_response_size;
  spdm_fragment_rsp_request_t  my_request;
  uintn                        my_request_size;

  ASSERT (*response_size <= (uint32)-1);

  received_response_size = 0;
  while (TRUE) {
    my_response_size = sizeof(my_response);
    zero_mem (&my_response, sizeof(my_response));
    status = spdm_receive_spdm_response (spdm_context, session_id, &my_response_size, &my_response);
    if (RETURN_ERROR(status)) {
      return status;
    }
    if (my_response_size < sizeof(spdm_fragment_response_t)) {
      return RETURN_DEVICE_ERROR;
    }
    if (my_response.header.request_response_code != SPDM_FRAGMENT_RESPONSE) {
      return RETURN_DEVICE_ERROR;
    }
    if (my_response.length > my_response_size - sizeof(spdm_fragment_response_t)) {
      return RETURN_DEVICE_ERROR;
    }

    if ((my_response.header.param1 & SPDM_FRAGMENT_REQUEST_ATTRIBUTER_BEGIN) != 0) {
      if (my_response.offset != 0) {
        return RETURN_DEVICE_ERROR;
      }
      received_response_size = 0;
    }

    if (my_response.offset != received_response_size) {
      return RETURN_DEVICE_ERROR;
    }

    if (my_response.offset > *response_size) {
      return RETURN_DEVICE_ERROR;
    }
    if (my_response.length > *response_size - my_response.offset) {
      return RETURN_DEVICE_ERROR;
    }

    copy_mem ((uint8 *)response + received_response_size, my_response.data, my_response.length);
    received_response_size += my_response.length;

    if ((my_response.header.param1 & SPDM_FRAGMENT_REQUEST_ATTRIBUTER_END) != 0) {
      break;
    }

    my_request.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    my_request.header.request_response_code = SPDM_FRAGMENT_RSP_REQUEST;
    my_request.header.param1 = 0;
    my_request.header.param2 = my_response.header.param2;
    my_request.sequence_id = my_response.sequence_id + 1;
    my_request_size = sizeof(my_request);
    status = spdm_send_spdm_request (spdm_context, session_id, my_request_size, &my_request);
    if (RETURN_ERROR(status)) {
      return RETURN_DEVICE_ERROR;
    }
  }

  *response_size = received_response_size;
  return RETURN_SUCCESS;
}
