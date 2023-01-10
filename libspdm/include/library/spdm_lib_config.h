/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_LIB_CONFIG_H__
#define __SPDM_LIB_CONFIG_H__

#define DEFAULT_CONTEXT_LENGTH            MAX_HASH_SIZE
#define DEFAULT_SECURE_MCTP_PADDING_SIZE  1

#define MAX_SPDM_PSK_HINT_LENGTH          16

#define MAX_SPDM_MEASUREMENT_BLOCK_COUNT  8
#define MAX_SPDM_SESSION_COUNT            4
#define MAX_SPDM_CERT_CHAIN_SIZE          0x20000
#define MAX_SPDM_MEASUREMENT_RECORD_SIZE  0x1000
#define MAX_SPDM_CERT_CHAIN_BLOCK_LEN     1024

#define MAX_SPDM_MESSAGE_LARGE_BUFFER_SIZE 0x20000
#define MAX_SPDM_MESSAGE_BUFFER_SIZE       0x2000
#define MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE 0x180

#define MAX_SPDM_REQUEST_RETRY_TIMES      3
#define MAX_SPDM_SESSION_STATE_CALLBACK_NUM     4
#define MAX_SPDM_CONNECTION_STATE_CALLBACK_NUM  4

#define MAX_SPDM_FRAGMENT_LENGTH  0x1000


//
// Crypto Configuation
// In each category, at least one should be selected.
//
#define OPENSPDM_RSA_SSA_SUPPORT                 1
#define OPENSPDM_RSA_PSS_SUPPORT                 1
#define OPENSPDM_ECDSA_SUPPORT                   1

#define OPENSPDM_FFDHE_SUPPORT                   1
#define OPENSPDM_ECDHE_SUPPORT                   1

#define OPENSPDM_AEAD_GCM_SUPPORT                1
#define OPENSPDM_AEAD_CHACHA20_POLY1305_SUPPORT  1

#define OPENSPDM_SHA256_SUPPORT      1
#define OPENSPDM_SHA384_SUPPORT      1
#define OPENSPDM_SHA512_SUPPORT      1

#endif
