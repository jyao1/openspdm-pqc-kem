/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_requester_emu.h"
#include "spdm_responder_emu.h"

extern void *m_server_spdm_context;

void *
spdm_server_init (
  void
  );

boolean
platform_client_routine (
  void
  );

int main (
  int argc,
  char *argv[ ]
  )
{
  //printf ("%s version 0.1\n", "spdm_perf_emu");
  srand((unsigned int)time(NULL));

  process_args ("spdm_perf_emu", argc, argv);

  //printf ("Init\n");
  m_server_spdm_context = spdm_server_init ();
  if (m_server_spdm_context == NULL) {
    return 0;
  }

  platform_client_routine ();
  //printf ("Stopped\n");

  perf_dump ();

  return 0;
}