/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_responder_lib_internal.h"

/**
  Process the SPDM FRAGMENT_REQUEST request and return the response.

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
spdm_get_response_fragment_request (
  IN     void                 *context,
  IN     uintn                request_size,
  IN     void                 *request,
  IN OUT uintn                *response_size,
     OUT void                 *response
  )
{
  spdm_context_t               *spdm_context;
  spdm_fragment_request_t      *my_request;
  spdm_fragment_request_ack_t  *my_response;
  spdm_get_spdm_response_func       get_response_func;
  return_status                     status;
  spdm_message_header_t             *spdm_request;
  boolean                           need_fragment_response;

  spdm_context = context;
  my_request = request;

  if (request_size < sizeof(spdm_fragment_request_t)) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
  if (request_size > sizeof(spdm_fragment_request_t) + MAX_SPDM_FRAGMENT_LENGTH) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
  if (request_size != sizeof(spdm_fragment_request_t) + my_request->length) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
  if (my_request->header.param1 & SPDM_FRAGMENT_REQUEST_ATTRIBUTER_BEGIN) {
    if (my_request->offset != 0) {
      spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
      return RETURN_SUCCESS;
    }
    spdm_context->last_spdm_fragment_encapsulated_request_size = 0;
  }

  if (my_request->offset != spdm_context->last_spdm_fragment_encapsulated_request_size) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
  if (my_request->length > MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE - my_request->offset) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }

  copy_mem (spdm_context->last_spdm_fragment_encapsulated_request + my_request->offset, my_request + 1, my_request->length);
  spdm_context->last_spdm_fragment_encapsulated_request_size = my_request->offset + my_request->length;

  if (my_request->header.param1 & SPDM_FRAGMENT_REQUEST_ATTRIBUTER_END) {
    spdm_request = (void *)spdm_context->last_spdm_fragment_encapsulated_request;
    status = RETURN_UNSUPPORTED;
    get_response_func = spdm_get_response_func_via_request_code (spdm_request->request_response_code);
    if (get_response_func != NULL) {
      need_fragment_response = spdm_need_fragment_response(spdm_request->request_response_code);
      if (need_fragment_response) {
        spdm_context->last_spdm_fragment_encapsulated_response_size = sizeof(spdm_context->last_spdm_fragment_encapsulated_response);
        spdm_context->last_spdm_fragment_encapsulated_response_sent_size = 0;
        status = get_response_func (spdm_context, spdm_context->last_spdm_fragment_encapsulated_request_size, spdm_context->last_spdm_fragment_encapsulated_request, &spdm_context->last_spdm_fragment_encapsulated_response_size, spdm_context->last_spdm_fragment_encapsulated_response);
        if (status == RETURN_SUCCESS) {
          status = spdm_build_fragment_response (spdm_context, response_size, response);
        }
      } else {
        status = get_response_func (spdm_context, spdm_context->last_spdm_fragment_encapsulated_request_size, spdm_context->last_spdm_fragment_encapsulated_request, response_size, response);
      }
    }
    if (status != RETURN_SUCCESS) {
      spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, spdm_request->request_response_code, response_size, response);
    }

    return RETURN_SUCCESS;
  }

  ASSERT (*response_size >= sizeof(spdm_fragment_request_ack_t));
  zero_mem (response, *response_size);
  my_response = response;
  *response_size = sizeof(spdm_fragment_request_ack_t);

  my_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
  my_response->header.request_response_code = SPDM_FRAGMENT_REQUEST_ACK;
  my_response->header.param1 = 0;
  my_response->header.param2 = my_request->header.param2;
  my_response->sequence_id = my_request->sequence_id;

  return RETURN_SUCCESS;
}

/**
  Process the SPDM FRAGMENT_RSP_REQUEST request and return the response.

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
spdm_get_response_fragment_rsp_request (
  IN     void                 *context,
  IN     uintn                request_size,
  IN     void                 *request,
  IN OUT uintn                *response_size,
     OUT void                 *response
  )
{
  spdm_context_t               *spdm_context;
  spdm_fragment_rsp_request_t  *my_request;
  spdm_fragment_response_t     *my_response;
  uint32                       offset;
  uint32                       length;

  spdm_context = context;
  my_request = request;

  if (request_size != sizeof(spdm_fragment_rsp_request_t)) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }
  if (spdm_context->last_spdm_fragment_encapsulated_response_size == spdm_context->last_spdm_fragment_encapsulated_response_sent_size) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }

  ASSERT (*response_size >= sizeof(spdm_fragment_response_t) + MAX_SPDM_FRAGMENT_LENGTH);
  zero_mem (response, *response_size);
  my_response = response;

  ASSERT (spdm_context->last_spdm_fragment_encapsulated_response_size <= (uint32)-1);
  ASSERT (spdm_context->last_spdm_fragment_encapsulated_response_size > spdm_context->last_spdm_fragment_encapsulated_response_sent_size);
  offset = (uint32)spdm_context->last_spdm_fragment_encapsulated_response_sent_size;
  length = MAX_SPDM_FRAGMENT_LENGTH;
  if (length > spdm_context->last_spdm_fragment_encapsulated_response_size - spdm_context->last_spdm_fragment_encapsulated_response_sent_size) {
    length = (uint32)(spdm_context->last_spdm_fragment_encapsulated_response_size - spdm_context->last_spdm_fragment_encapsulated_response_sent_size);
  }

  my_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
  my_response->header.request_response_code = SPDM_FRAGMENT_RESPONSE;
  my_response->header.param1 = 0;
  if (offset == 0) {
    my_response->header.param1 |= SPDM_FRAGMENT_RESPONSE_ATTRIBUTER_BEGIN;
  }
  if (length + offset == spdm_context->last_spdm_fragment_encapsulated_response_size) {
    my_response->header.param1 |= SPDM_FRAGMENT_RESPONSE_ATTRIBUTER_END;
  }
  my_response->header.param2 = my_request->header.param2;
  my_response->sequence_id = my_request->sequence_id;

  my_response->offset = offset;
  my_response->length = length;
  copy_mem (my_response + 1, spdm_context->last_spdm_fragment_encapsulated_response + offset, length);
  *response_size = sizeof(spdm_fragment_response_t) + length;

  spdm_context->last_spdm_fragment_encapsulated_response_sent_size = offset + length;

  return RETURN_SUCCESS;
}

/**
  Build the SPDM FRAGMENT_RESPONSE.

  @param  spdm_context                  A pointer to the SPDM context.
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
spdm_build_fragment_response (
  IN     void                 *context,
  IN OUT uintn                *response_size,
     OUT void                 *response
  )
{
  uint8                       response_id;
  spdm_context_t               *spdm_context;
  spdm_fragment_response_t     *my_response;
  uint32                       offset;
  uint32                       length;

  spdm_context = context;

  response_id = 0xff;

  if (spdm_context->last_spdm_fragment_encapsulated_response_size == spdm_context->last_spdm_fragment_encapsulated_response_sent_size) {
    spdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
    return RETURN_SUCCESS;
  }

  ASSERT (*response_size >= sizeof(spdm_fragment_response_t) + MAX_SPDM_FRAGMENT_LENGTH);
  zero_mem (response, *response_size);
  my_response = response;

  ASSERT (spdm_context->last_spdm_fragment_encapsulated_response_size <= (uint32)-1);
  ASSERT (spdm_context->last_spdm_fragment_encapsulated_response_size > spdm_context->last_spdm_fragment_encapsulated_response_sent_size);
  offset = (uint32)spdm_context->last_spdm_fragment_encapsulated_response_sent_size;
  length = MAX_SPDM_FRAGMENT_LENGTH;
  if (length > spdm_context->last_spdm_fragment_encapsulated_response_size - spdm_context->last_spdm_fragment_encapsulated_response_sent_size) {
    length = (uint32)(spdm_context->last_spdm_fragment_encapsulated_response_size - spdm_context->last_spdm_fragment_encapsulated_response_sent_size);
  }

  my_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
  my_response->header.request_response_code = SPDM_FRAGMENT_RESPONSE;
  my_response->header.param1 = 0;
  if (offset == 0) {
    my_response->header.param1 |= SPDM_FRAGMENT_RESPONSE_ATTRIBUTER_BEGIN;
  }
  if (length + offset == spdm_context->last_spdm_fragment_encapsulated_response_size) {
    my_response->header.param1 |= SPDM_FRAGMENT_RESPONSE_ATTRIBUTER_END;
  }
  my_response->header.param2 = response_id;
  my_response->sequence_id = 0;

  my_response->offset = offset;
  my_response->length = length;
  copy_mem (my_response + 1, spdm_context->last_spdm_fragment_encapsulated_response + offset, length);
  *response_size = sizeof(spdm_fragment_response_t) + length;

  spdm_context->last_spdm_fragment_encapsulated_response_sent_size = offset + length;

  return RETURN_SUCCESS;
}
