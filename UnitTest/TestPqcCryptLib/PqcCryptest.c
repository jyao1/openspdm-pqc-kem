/** @file
  Application for Cryptographic Primitives Validation.

Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PqcCryptest.h"

UINTN
EFIAPI
AsciiStrLen (
  IN      CONST CHAR8               *String
  )
{
  UINTN                             Length;

  ASSERT (String != NULL);
  if (String == NULL) {
    return 0;
  }

  for (Length = 0; *String != '\0'; String++, Length++) {
    ;
  }
  return Length;
}

VOID
Print (
  IN CHAR8 *Message
  )
{
  DebugPrint(DEBUG_INFO, "%s", Message);
}

VOID
PrintData (
  IN CHAR8 *Message,
  IN UINTN  Data
  )
{
  DebugPrint(DEBUG_INFO, Message, Data);
}

/**
  Entry Point of Cryptographic Validation Utility.

  @param  ImageHandle  The image handle of the UEFI Application.
  @param  SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
PqcCryptestMain (
  IN     EFI_HANDLE                 ImageHandle,
  IN     EFI_SYSTEM_TABLE           *SystemTable
  )
{
  EFI_STATUS  Status;

  Print ("\nUEFI-OQS Wrapper Cryptosystem Testing: \n");
  Print ("-------------------------------------------- \n");

  //RandomSeed (NULL, 0);

  Status = ValidatePqcCryptSig ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ValidatePqcCryptKem ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

int main(void)
{
  PqcCryptestMain(NULL, NULL);
  return 0;
}