/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_emu.h"

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
#if 0
#ifdef _MSC_VER
  printf ("freq: %I64d MHz\n", m_freq_mh);
#else
  printf ("freq: %lld MHz\n", m_freq_mh);
#endif
#endif
}

char *m_perf_str[] = {
  "RESERVED",
  "REQUESTER",
  "RESPONDER",
  "CERT_VERIFICATION",
  "CHALLENG_SIG_GEN",
  "CHALLENG_SIG_VER",
  "CHALLENG_KEM_AUTH_ENCAP",
  "CHALLENG_KEM_AUTH_DECAP",
  "KEY_EX_KEM_GEN",
  "KEY_EX_KEM_ENCAP",
  "KEY_EX_KEM_DECAP",
  "KEY_EX_SIG_GEN",
  "KEY_EX_SIG_VER",
  "KEY_EX_KEM_AUTH_ENCAP",
  "KEY_EX_KEM_AUTH_DECAP",
  "CHALLENG_RSP_SIG_GEN",
  "CHALLENG_RSP_SIG_VER",
  "CHALLENG_RSP_KEM_AUTH_ENCAP",
  "CHALLENG_RSP_KEM_AUTH_DECAP",
  "FINISH_RSP_SIG_GEN",
  "FINISH_RSP_SIG_VER",
  "KEY_EX_RSP_KEM_AUTH_ENCAP",
  "KEY_EX_RSP_KEM_AUTH_DECAP",
  "MAX",
};

int
get_security_level (
  uint16 dhe_algo,
  pqc_algo_t pqc_kem_algo,
  uint32 asym_algo,
  pqc_algo_t pqc_sig_algo)
{
  uintn  nid;
  if (dhe_algo == SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1) {
    return 5;
  } else if (dhe_algo == SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1) {
    return 3;
  } else if (dhe_algo == SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1) {
    return 1;
  } else {
    nid = spdm_get_pqc_kem_nid (pqc_kem_algo);
    if (nid == PQC_CRYPTO_KEM_NID_KYBER_1024 ||
        nid == PQC_CRYPTO_KEM_NID_KYBER_1024_90S) {
      return 5;
    } else if (nid == PQC_CRYPTO_KEM_NID_KYBER_768 ||
               nid == PQC_CRYPTO_KEM_NID_KYBER_768_90S) {
      return 3;
    } else if (nid == PQC_CRYPTO_KEM_NID_KYBER_512 ||
               nid == PQC_CRYPTO_KEM_NID_KYBER_512_90S) {
      return 1;
    }
  }
  return 0;
}

typedef struct {
  uint32 algo;
  char *name;
} algo_name_struct_t;

algo_name_struct_t m_dhe_algo_struct[] = {
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1, "p256"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1, "p384"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1, "p521"},
};

char *dhe_algo_to_string (uint32 algo)
{
  uint32 index;
  for (index = 0; index < ARRAY_SIZE(m_dhe_algo_struct); index++) {
    if (algo == m_dhe_algo_struct[index].algo) {
      return m_dhe_algo_struct[index].name;
    }
  }
  return "<unknown>";
}

algo_name_struct_t m_asym_algo_struct[] = {
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072, "rsa3072"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072, "rsa3072"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, "p256"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384, "p384"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521, "p521"},
};

char *asym_algo_to_string (uint32 algo)
{
  uint32 index;
  for (index = 0; index < ARRAY_SIZE(m_asym_algo_struct); index++) {
    if (algo == m_asym_algo_struct[index].algo) {
      return m_asym_algo_struct[index].name;
    }
  }
  return "<unknown>";
}

char *pqc_kem_algo_to_string (pqc_algo_t pqc_algo)
{
  uintn  nid;
  pqc_oqs_algo_table_t  *algo_entry;

  nid = spdm_get_pqc_kem_nid (pqc_algo);
  if (nid == 0) {
    return "<unknown>";
  }
  algo_entry = pqc_get_oqs_kem_algo_entry (nid);
  if (algo_entry == NULL) {
    return "<unknown>";
  }
  return algo_entry->name;
}

char *pqc_sig_algo_to_string (pqc_algo_t pqc_algo)
{
  uintn  nid;
  pqc_oqs_algo_table_t  *algo_entry;

  nid = spdm_get_pqc_sig_nid (pqc_algo);
  if (nid == 0) {
    return "<unknown>";
  }
  algo_entry = pqc_get_oqs_sig_algo_entry (nid);
  if (algo_entry == NULL) {
    return "<unknown>";
  }
  return algo_entry->name;
}

void
perf_dump ()
{
  boolean need_flag;
  calibration ();
#if 1
  // | Security Level | Configuration (KEM + SIG + KEM_AUTH)
  printf ("| %d | ", get_security_level (m_use_dhe_algo, m_use_pqc_kem_algo, m_use_asym_algo, m_use_pqc_sig_algo));
  need_flag = FALSE;
  if (m_use_dhe_algo != 0) {
    printf ("%s", dhe_algo_to_string (m_use_dhe_algo));
    need_flag = TRUE;
  }
  if (!spdm_pqc_algo_is_zero (m_use_pqc_kem_algo)) {
    if (need_flag) {
      printf ("_");
    }
    printf ("%s", pqc_kem_algo_to_string (m_use_pqc_kem_algo));
  }
  printf (" + ");
  need_flag = FALSE;
  if (m_use_asym_algo != 0) {
    printf ("%s", asym_algo_to_string (m_use_asym_algo));
    need_flag = TRUE;
  }
  if (!spdm_pqc_algo_is_zero (m_use_pqc_sig_algo)) {
    if (need_flag) {
      printf ("_");
    }
    printf ("%s", pqc_sig_algo_to_string (m_use_pqc_sig_algo));
    need_flag = TRUE;
  }
  if (!spdm_pqc_algo_is_zero (m_use_pqc_kem_auth_algo)) {
    if (need_flag) {
      printf ("_");
    }
    printf ("%s", pqc_kem_algo_to_string (m_use_pqc_kem_auth_algo));
  }

  // | Requester TOTAL | CERT_VERIFY | CHAL_VERIFY | CHAL_KEM_AUTH_ENCAP | KEY_EX_KEM_GEN | KEY_EX_KEM_DECAP | KEY_EX_KEM_VERIFY | KEY_EX_KEM_AUTH_ENCAP
#ifdef _MSC_VER
  printf (" | %I64d | %I64d | %I64d | %I64d | %I64d | %I64d | %I64d | %I64d | %I64d ",
#else
  printf (" | %lld | %lld | %lld | %lld | %lld | %lld | %lld | %lld | %lld ",
#endif
    m_perf_struct[PERF_ID_REQUESTER].sum / m_freq_mh,
    m_perf_struct[PERF_ID_CERT_VERIFICATION].sum / m_freq_mh,
    m_perf_struct[PERF_ID_CHALLENG_SIG_VER].sum / m_freq_mh,
    m_perf_struct[PERF_ID_CHALLENG_KEM_AUTH_ENCAP].sum / m_freq_mh,
    m_perf_struct[PERF_ID_KEY_EX_KEM_GEN].sum / m_freq_mh,
    m_perf_struct[PERF_ID_KEY_EX_KEM_DECAP].sum / m_freq_mh,
    m_perf_struct[PERF_ID_KEY_EX_SIG_VER].sum / m_freq_mh,
    m_perf_struct[PERF_ID_KEY_EX_KEM_AUTH_ENCAP].sum / m_freq_mh,
    m_perf_struct[PERF_ID_REQUESTER].sum / m_freq_mh -
      m_perf_struct[PERF_ID_CERT_VERIFICATION].sum / m_freq_mh -
      m_perf_struct[PERF_ID_CHALLENG_SIG_VER].sum / m_freq_mh -
      m_perf_struct[PERF_ID_CHALLENG_KEM_AUTH_ENCAP].sum / m_freq_mh -
      m_perf_struct[PERF_ID_KEY_EX_KEM_GEN].sum / m_freq_mh -
      m_perf_struct[PERF_ID_KEY_EX_KEM_DECAP].sum / m_freq_mh -
      m_perf_struct[PERF_ID_KEY_EX_SIG_VER].sum / m_freq_mh - 
      m_perf_struct[PERF_ID_KEY_EX_KEM_AUTH_ENCAP].sum / m_freq_mh
    );
  // Responder TOTAL | CHAL_SIGN | CHAL_KEM_AUTH_DECAP | KEY_EX_KEM_ENCAP | KEY_EX_KEM_SIGN | KEY_EX_KEM_AUTH_DECAP |
#ifdef _MSC_VER
  printf ("| %I64d | %I64d | %I64d | %I64d | %I64d | %I64d | %I64d |\n",
#else
  printf ("| %lld | %lld | %lld | %lld | %lld | %lld | %lld |\n",
#endif
    m_perf_struct[PERF_ID_RESPONDER].sum / m_freq_mh,
    m_perf_struct[PERF_ID_CHALLENG_SIG_GEN].sum / m_freq_mh,
    m_perf_struct[PERF_ID_CHALLENG_KEM_AUTH_DECAP].sum / m_freq_mh,
    m_perf_struct[PERF_ID_KEY_EX_KEM_ENCAP].sum / m_freq_mh,
    m_perf_struct[PERF_ID_KEY_EX_SIG_GEN].sum / m_freq_mh,
    m_perf_struct[PERF_ID_KEY_EX_KEM_AUTH_DECAP].sum / m_freq_mh,
    m_perf_struct[PERF_ID_RESPONDER].sum / m_freq_mh -
      m_perf_struct[PERF_ID_CHALLENG_SIG_GEN].sum / m_freq_mh -
      m_perf_struct[PERF_ID_CHALLENG_KEM_AUTH_DECAP].sum / m_freq_mh -
      m_perf_struct[PERF_ID_KEY_EX_KEM_ENCAP].sum / m_freq_mh -
      m_perf_struct[PERF_ID_KEY_EX_SIG_GEN].sum / m_freq_mh -
      m_perf_struct[PERF_ID_KEY_EX_KEM_AUTH_DECAP].sum / m_freq_mh
    );
#else
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
#endif
}

