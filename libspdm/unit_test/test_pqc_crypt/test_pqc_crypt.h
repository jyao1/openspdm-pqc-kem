/** @file
  Application for Cryptographic Primitives Validation.

Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __PQC_CRYPTEST_H__
#define __PQC_CRYPTEST_H__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#undef NULL

#include <hal/base.h>

#include <library/debuglib.h>
#include <library/memlib.h>
#include <library/malloclib.h>
#include <library/pqc_crypt_lib.h>

boolean
read_input_file (
  IN char8    *file_name,
  OUT void    **file_data,
  OUT uintn   *file_size
  );

boolean
write_output_file (
  IN char8   *file_name,
  IN void    *file_data,
  IN uintn   file_size
  );

uintn
ascii_str_len (
  IN      const char8               *string
  );

void
my_print (
  IN char8 *message
  );

void
my_print_data (
  IN char8 *message,
  IN uintn  data
  );

/**
  Validate PQC SIG Interfaces.

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status
validate_pqc_crypt_sig (
  void
  );

/**
  Validate PQC KEM Interfaces.

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status
validate_pqc_crypt_kem (
  void
  );

/**
  Validate PQC hybrid SIG Interfaces.

  @retval  RETURN_SUCCESS  Validation succeeded.
  @retval  RETURN_ABORTED  Validation failed.

**/
return_status
validate_pqc_crypt_hybrid_sig (
  void
  );

typedef enum {
  PERF_ID_RESERVED,
  PERF_ID_KEM_GEN,
  PERF_ID_KEM_ENCAP,
  PERF_ID_KEM_DECAP,
  PERF_ID_SIG_GEN,
  PERF_ID_SIG_VER,
  PERF_ID_MAX,
} perf_id_t;

void
calibration ();

uint64
perf_start (perf_id_t perf_id);

uint64
perf_stop (perf_id_t perf_id);

void
perf_dump ();

#endif
