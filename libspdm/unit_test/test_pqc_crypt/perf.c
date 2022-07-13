/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "test_pqc_crypt.h"

#include <windows.h>

typedef struct {
  uint64  start;
  uint64  stop;
  uint64  sum;
  uint32  count;
  boolean run;
} perf_struct_t;

perf_struct_t m_perf_struct[PERF_ID_MAX];

uint64
readtsc ()
{
#ifdef _MSC_VER
  return __rdtsc();
#else
  uint32  LowData;
  uint32  HiData;

  __asm__ __volatile__ (
    "rdtsc"
    : "=a" (LowData),
      "=d" (HiData)
  );

  return (((uint64)HiData) << 32) | LowData;
#endif
}

void
mysleep (uint32 milliseconds)
{
#ifdef _MSC_VER
  Sleep (milliseconds);
#else
  struct timeval tv;
  int err;

  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;

  do {
    err=select(0, NULL, NULL, NULL, &tv);
  } while(err<0 && errno==EINTR);
#endif
}

uint64
perf_start (perf_id_t perf_id)
{
  ASSERT (perf_id < PERF_ID_MAX);
  ASSERT (!m_perf_struct[perf_id].run);
  m_perf_struct[perf_id].run = TRUE;
  m_perf_struct[perf_id].start = readtsc();
  return m_perf_struct[perf_id].start;
}

uint64
perf_stop (perf_id_t perf_id)
{
  m_perf_struct[perf_id].stop = readtsc();
  ASSERT (perf_id < PERF_ID_MAX);
  ASSERT (m_perf_struct[perf_id].run);
  m_perf_struct[perf_id].run = FALSE;
  m_perf_struct[perf_id].sum += (m_perf_struct[perf_id].stop - m_perf_struct[perf_id].start);
  m_perf_struct[perf_id].count ++;
  return m_perf_struct[perf_id].stop;
}

/*
  tsc / freq = (tsc / 1000000) / (freq / 1000000) sec
             = (tsc / 1000) / (freq / 1000000) mill-sec
*/

uint64 m_freq_mh;

void calibration ()
{
  uint64 tsc_start;
  uint64 tsc_end;

  tsc_start = readtsc ();
  // stall 1 sec
  mysleep (1000);
  tsc_end = readtsc ();
  m_freq_mh = (tsc_end - tsc_start) / 1000 / 1000;
#if 1
#ifdef _MSC_VER
  printf ("freq: %I64d MHz\n", m_freq_mh);
#else
  printf ("freq: %lld MHz\n", m_freq_mh);
#endif
#endif
}

char *m_perf_str[] = {
  "RESERVED",
  "KEM_GEN",
  "KEM_ENCAP",
  "KEM_DECAP",
  "SIG_GEN",
  "SIG_VER",
  "MAX",
};

void
perf_dump ()
{
  calibration ();

  perf_id_t perf_id;
  for (perf_id = PERF_ID_RESERVED; perf_id < PERF_ID_MAX; perf_id++) {
    if (m_perf_struct[perf_id].sum == 0) {
      continue;
    }
    printf ("perf_id - %d (%s)\n", perf_id, m_perf_str[perf_id]);
    printf ("  count - %d\n", m_perf_struct[perf_id].count);
#ifdef _MSC_VER
    printf ("  tsc - %I64d\n", m_perf_struct[perf_id].sum);
    printf ("  time - %I64d usec\n", m_perf_struct[perf_id].sum / m_freq_mh);
#else
    printf ("  tsc - %lld\n", m_perf_struct[perf_id].sum);
    printf ("  time - %lld usec\n", m_perf_struct[perf_id].sum / m_freq_mh);
#endif
  }
}

