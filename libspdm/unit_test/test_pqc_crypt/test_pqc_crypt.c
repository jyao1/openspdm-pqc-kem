/** @file
  Application for Cryptographic Primitives Validation.

Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "test_pqc_crypt.h"

uintn
ascii_str_len (
  IN      const char8               *string
  )
{
  uintn                             length;

  ASSERT (string != NULL);
  if (string == NULL) {
    return 0;
  }

  for (length = 0; *string != '\0'; string++, length++) {
    ;
  }
  return length;
}

void
my_print (
  IN char8 *message
  )
{
  debug_print(DEBUG_INFO, "%s", message);
}

void
my_print_data (
  IN char8 *message,
  IN uintn  data
  )
{
  debug_print(DEBUG_INFO, message, data);
}

/**
  Entry Point of Cryptographic Validation Utility.

  @param  ImageHandle  The image handle of the UEFI Application.
  @param  SystemTable  A pointer to the EFI System Table.

  @retval RETURN_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
return_status
pqc_cryptest_main (
  void
  )
{
  return_status  status;

  my_print ("\nPQC Wrapper Cryptosystem Testing: \n");
  my_print ("-------------------------------------------- \n");

  //RandomSeed (NULL, 0);

  status = validate_pqc_crypt_hybrid_sig ();
  if (RETURN_ERROR (status)) {
    return status;
  }

  status = validate_pqc_crypt_kem ();
  if (RETURN_ERROR (status)) {
    return status;
  }

  status = validate_pqc_crypt_sig ();
  if (RETURN_ERROR (status)) {
    return status;
  }

  return RETURN_SUCCESS;
}

int main(void)
{
  pqc_cryptest_main();
  return 0;
}