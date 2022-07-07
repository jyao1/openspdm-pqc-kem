/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_emu.h"

uint32  m_use_transport_layer = SOCKET_TRANSPORT_TYPE_MCTP;

uint8   m_socket_buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE + sizeof(socket_buffer_header_t)];
boolean m_socket_buffer_ready;

/**
  Read number of bytes data in blocking mode.

  If there is no enough data in socket, this function will wait.
  This function will return if enough data is read, or socket error.
**/
boolean
read_bytes (
  IN  SOCKET          socket,
  OUT uint8           *buffer,
  IN  uint32          number_of_bytes
  )
{
  int32                 result;
  uint32                number_received;

  number_received = 0;
  while (number_received < number_of_bytes) {
    result = recv (socket, (char8 *)(buffer + number_received), number_of_bytes - number_received, 0);
    if (result == -1) {
      printf ("Receive error - 0x%x\n",
#ifdef _MSC_VER
        WSAGetLastError()
#else
        errno
#endif
        );
      return FALSE;
    }
    if (result == 0) {
      return FALSE;
    }
    number_received += result;
  }
  return TRUE;
}

boolean
read_data32 (
  IN SOCKET           socket,
  OUT uint32          *data
  )
{
  boolean  result;

  result = read_bytes (socket, (uint8 *)data, sizeof(uint32));
  if (!result) {
    return result;
  }
  *data = ntohl (*data);
  return TRUE;
}

/**
  Read multiple bytes in blocking mode.

  The length is presented as first 4 bytes in big endian.
  The data follows the length.

  If there is no enough data in socket, this function will wait.
  This function will return if enough data is read, or socket error.
**/
boolean
read_multiple_bytes (
  IN SOCKET           socket,
  OUT uint8           *buffer,
  OUT uint32          *bytes_received,
  IN uint32           max_buffer_length
  )
{
  uint32               length;
  boolean              result;

  result = read_data32 (socket, &length);
  if (!result) {
    return result;
  }
  DEBUG ((DEBUG_INFO, "Platform port Receive size: "));
  length = ntohl(length);
  dump_data ((uint8 *)&length, sizeof(uint32));
  DEBUG ((DEBUG_INFO, "\n"));
  length = ntohl(length);

  *bytes_received = length;
  if (*bytes_received > max_buffer_length) {
    printf ("buffer too small (0x%x). Expected - 0x%x\n", max_buffer_length, *bytes_received);
    return FALSE;
  }
  if (length == 0) {
    return TRUE;
  }
  result = read_bytes (socket, buffer, length);
  if (!result) {
    return result;
  }
  DEBUG ((DEBUG_INFO, "Platform port Receive buffer:\n    "));
  dump_data (buffer, length);
  DEBUG ((DEBUG_INFO, "\n"));

  return TRUE;
}

boolean
receive_platform_data_socket_buffer (
  OUT uint32           *command,
  OUT uint8            *receive_buffer,
  IN OUT uintn         *bytes_to_receive
  )
{
  socket_buffer_header_t *socket_buffer_header;

  ASSERT (m_socket_buffer_ready);

  socket_buffer_header = (void *)m_socket_buffer;
  *command = htonl(socket_buffer_header->command);
  ASSERT (htonl(socket_buffer_header->payload_size) <= sizeof(m_socket_buffer) - sizeof(socket_buffer_header_t));
  ASSERT (*bytes_to_receive >= htonl(socket_buffer_header->payload_size));
  *bytes_to_receive= htonl(socket_buffer_header->payload_size);

  copy_mem (receive_buffer, (void *)(socket_buffer_header + 1), *bytes_to_receive);

  m_socket_buffer_ready = FALSE;
  return TRUE;
}

boolean
receive_platform_data (
  IN  SOCKET           socket,
  OUT uint32           *command,
  OUT uint8            *receive_buffer,
  IN OUT uintn         *bytes_to_receive
  )
{
  boolean  result;
  uint32   response;
  uint32   transport_type;
  uint32   bytes_received;

  if (socket == 0) {
    return receive_platform_data_socket_buffer(command, receive_buffer, bytes_to_receive);
  }

  result = read_data32 (socket, &response);
  if (!result) {
    return result;
  }
  *command = response;
  DEBUG ((DEBUG_INFO, "Platform port Receive command: "));
  response = ntohl(response);
  dump_data ((uint8 *)&response, sizeof(uint32));
  DEBUG ((DEBUG_INFO, "\n"));

  result = read_data32 (socket, &transport_type);
  if (!result) {
    return result;
  }
  DEBUG ((DEBUG_INFO, "Platform port Receive transport_type: "));
  transport_type = ntohl(transport_type);
  dump_data ((uint8 *)&transport_type, sizeof(uint32));
  DEBUG ((DEBUG_INFO, "\n"));
  transport_type = ntohl(transport_type);
  if (transport_type != m_use_transport_layer) {
    printf ("transport_type mismatch\n");
    return FALSE;
  }

  bytes_received = 0;
  result = read_multiple_bytes (socket, receive_buffer, &bytes_received, (uint32)*bytes_to_receive);
  if (!result) {
    return result;
  }
  *bytes_to_receive = bytes_received;

  switch (*command) {
  case SOCKET_SPDM_COMMAND_SHUTDOWN:
    close_pcap_packet_file ();
    break;
  case SOCKET_SPDM_COMMAND_NORMAL:
    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
      //
      // Append mctp_header_t for PCAP
      //
      mctp_header_t  mctp_header;
      mctp_header.header_version = 0;
      mctp_header.destination_id = 0;
      mctp_header.source_id = 0;
      mctp_header.message_tag = 0xC0;
      append_pcap_packet_data (&mctp_header, sizeof(mctp_header), receive_buffer, bytes_received);
    } else {
      append_pcap_packet_data (NULL, 0, receive_buffer, bytes_received);
    }
    break;
  }

  return result;
}

/**
  Write number of bytes data in blocking mode.

  This function will return if data is written, or socket error.
**/
boolean
write_bytes(
  IN  SOCKET           socket,
  IN  uint8            *buffer,
  IN  uint32           number_of_bytes
  )
{
  int32                result;
  uint32               number_sent;

  number_sent = 0;
  while (number_sent < number_of_bytes) {
    result = send (socket, (char8 *)(buffer + number_sent), number_of_bytes - number_sent, 0);
    if (result == -1) {
#ifdef _MSC_VER
      if (WSAGetLastError() == 0x2745) {
        printf ("Client disconnected\n");
      } else {
#endif
        printf ("Send error - 0x%x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
#ifdef _MSC_VER
      }
#endif
      return FALSE;
    }
    number_sent += result;
  }
  return TRUE;
}

boolean
write_data32 (
  IN SOCKET           socket,
  IN uint32           data
  )
{
  data = htonl(data);
  return write_bytes (socket, (uint8 *)&data, sizeof(uint32));
}

/**
  Write multiple bytes.

  The length is presented as first 4 bytes in big endian.
  The data follows the length.
**/
boolean
write_multiple_bytes (
  IN SOCKET           socket,
  IN uint8            *buffer,
  IN uint32           bytes_to_send
  )
{
  boolean  result;

  result = write_data32 (socket, bytes_to_send);
  if (!result) {
    return result;
  }
  DEBUG ((DEBUG_INFO, "Platform port Transmit size: "));
  bytes_to_send = htonl(bytes_to_send);
  dump_data ((uint8 *)&bytes_to_send, sizeof(uint32));
  DEBUG ((DEBUG_INFO, "\n"));
  bytes_to_send = htonl(bytes_to_send);

  result = write_bytes (socket, buffer, bytes_to_send);
  if (!result) {
    return result;
  }
  DEBUG ((DEBUG_INFO, "Platform port Transmit buffer:\n    "));
  dump_data (buffer, bytes_to_send);
  DEBUG ((DEBUG_INFO, "\n"));
  return TRUE;
}

boolean
send_platform_data_socket_buffer (
  IN uint32           command,
  IN uint8            *send_buffer,
  IN uintn            bytes_to_send
  )
{
  socket_buffer_header_t *socket_buffer_header;

  ASSERT (!m_socket_buffer_ready);
  ASSERT (bytes_to_send <= sizeof(m_socket_buffer) - sizeof(socket_buffer_header_t));

  socket_buffer_header = (void *)m_socket_buffer;
  socket_buffer_header->command = htonl(command);
  socket_buffer_header->transport_type = htonl(m_use_transport_layer);
  socket_buffer_header->payload_size = htonl((uint32)bytes_to_send);
  copy_mem ((void *)(socket_buffer_header + 1), send_buffer, bytes_to_send);

  m_socket_buffer_ready = TRUE;
  return TRUE;
}

boolean
send_platform_data (
  IN SOCKET           socket,
  IN uint32           command,
  IN uint8            *send_buffer,
  IN uintn            bytes_to_send
  )
{
  boolean  result;
  uint32   request;
  uint32   transport_type;

  if (socket == 0) {
    return send_platform_data_socket_buffer(command, send_buffer, bytes_to_send);
  }

  request = command;
  result = write_data32 (socket, request);
  if (!result) {
    return result;
  }
  DEBUG ((DEBUG_INFO, "Platform port Transmit command: "));
  request = htonl(request);
  dump_data ((uint8 *)&request, sizeof(uint32));
  DEBUG ((DEBUG_INFO, "\n"));

  result = write_data32 (socket, m_use_transport_layer);
  if (!result) {
    return result;
  }
  DEBUG ((DEBUG_INFO, "Platform port Transmit transport_type: "));
  transport_type = ntohl(m_use_transport_layer);
  dump_data ((uint8 *)&transport_type, sizeof(uint32));
  DEBUG ((DEBUG_INFO, "\n"));

  result = write_multiple_bytes (socket, send_buffer, (uint32)bytes_to_send);
  if (!result) {
    return result;
  }

  switch (command) {
  case SOCKET_SPDM_COMMAND_SHUTDOWN:
    close_pcap_packet_file ();
    break;
  case SOCKET_SPDM_COMMAND_NORMAL:
    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
      //
      // Append mctp_header_t for PCAP
      //
      mctp_header_t  mctp_header;
      mctp_header.header_version = 0;
      mctp_header.destination_id = 0;
      mctp_header.source_id = 0;
      mctp_header.message_tag = 0xC0;
      append_pcap_packet_data (&mctp_header, sizeof(mctp_header), send_buffer, bytes_to_send);
    } else {
      append_pcap_packet_data (NULL, 0, send_buffer, bytes_to_send);
    }
    break;
  }

  return TRUE;
}
