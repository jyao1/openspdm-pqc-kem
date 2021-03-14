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
#include <assert.h>
#undef NULL

#include <Hal/Base.h>

#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PqcCryptLib.h>


#define IN
#define OUT
#define EFI_HANDLE VOID*
#define EFI_SYSTEM_TABLE VOID*
#define EFI_STATUS RETURN_STATUS
#define EFI_ERROR(StatusCode) (((INTN)(RETURN_STATUS)(StatusCode)) < 0)
#define EFI_SUCCESS 0
#define EFI_ABORTED RETURN_ABORTED


BOOLEAN
ReadInputFile (
  IN CHAR8    *FileName,
  OUT VOID    **FileData,
  OUT UINTN   *FileSize
  );

UINTN
EFIAPI
AsciiStrLen (
  IN      CONST CHAR8               *String
  );

VOID
Print (
  IN CHAR8 *Message
  );

VOID
PrintData (
  IN CHAR8 *Message,
  IN UINTN  Data
  );

/**
  Validate UEFI-OQS SIG Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidatePqcCryptSig (
  VOID
  );

/**
  Validate UEFI-OQS KEM Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidatePqcCryptKem (
  VOID
  );

#endif
