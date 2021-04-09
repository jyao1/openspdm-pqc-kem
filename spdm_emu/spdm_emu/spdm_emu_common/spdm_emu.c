/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_emu.h"

/*
  EXE_MODE_SHUTDOWN
  EXE_MODE_CONTINUE
*/
uint32  m_exe_mode = EXE_MODE_SHUTDOWN;

uint32  m_exe_connection = (0 |
                          // EXE_CONNECTION_VERSION_ONLY |
                          EXE_CONNECTION_DIGEST |
                          EXE_CONNECTION_CERT |
                          EXE_CONNECTION_CHAL |
                          EXE_CONNECTION_MEAS |
                          0);

uint32  m_exe_session = (0 |
                       EXE_SESSION_KEY_EX |
                       EXE_SESSION_PSK |
                       // EXE_SESSION_NO_END |
                       EXE_SESSION_KEY_UPDATE |
                       EXE_SESSION_HEARTBEAT |
                       EXE_SESSION_MEAS |
                       0);

void
print_usage (
  IN char8* name
  )
{
  printf ("\n%s [--trans MCTP|PCI_DOE]\n", name);
  printf ("   [--ver 1.0|1.1]\n");
  printf ("   [--sec_ver 0|1.1]\n");
  printf ("   [--cap CACHE|CERT|CHAL|MEAS_NO_SIG|MEAS_SIG|MEAS_FRESH|ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|PSK_WITH_CONTEXT|ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID]\n");
  printf ("   [--hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]\n");
  printf ("   [--meas_spec DMTF]\n");
  printf ("   [--meas_hash RAW_BIT|SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]\n");
  printf ("   [--asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]\n");
  printf ("   [--req_asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]\n");
  printf ("   [--dhe FFDHE_2048|FFDHE_3072|FFDHE_4096|SECP_256_R1|SECP_384_R1|SECP_521_R1]\n");
  printf ("   [--aead AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305]\n");
  printf ("   [--key_schedule HMAC_HASH]\n");
  printf ("   [--pqc_sig DILITHIUM_{2,3,5}{_AES*}|FALCON_{512,1024}|RAINBOW_{I,III,V}_{CLASSIC,CIRCUMZENITHAL,COMPRESSED}|SPHINCS_{HARAKA,SHA256,SHAKE256}_{128,192,256}{F,S}_{ROBUST,SIMPLE}|PICNIC{3*}_L{1,3,5}_{FS,UR,FULL}]\n");
  printf ("   [--pqc_req_sig DILITHIUM_{2,3,5}{_AES*}|FALCON_{512,1024}|RAINBOW_{I,III,V}_{CLASSIC,CIRCUMZENITHAL,COMPRESSED}|SPHINCS_{HARAKA,SHA256,SHAKE256}_{128,192,256}{F,S}_{ROBUST,SIMPLE}|PICNIC{3*}_L{1,3,5}_{FS,UR,FULL}]\n");
  printf ("   [--pqc_kem BIKE1_{L1,L3}_{CPA,FO}|CLASSIC_MCELIECE_{348864,460896,6688128,6960119,8192128}{F*}|HQC_{128,192,256}|KYBER_{512,768,1024}{_90S*}|NTRU_{HPS_2048_{509,677,821},HRSS_701}|{NTRULPR,SNTRUP}{653,761,857}|{LIGHT,FIRE,*}SABER_KEM|FRODOKEM_{640,976,1344}_{AES,SHAKE}|SI{DH,KE}_P{434,503,610,751}{_COMPRESSED*}]\n");
  printf ("   [--pqc_pub_key_mode RAW|CERT]\n");
  printf ("   [--basic_mut_auth NO|BASIC]\n");
  printf ("   [--mut_auth NO|WO_ENCAP|W_ENCAP|DIGESTS]\n");
  printf ("   [--meas_sum NO|TCB|ALL]\n");
  printf ("   [--meas_op ONE_BY_ONE|ALL]\n");
  printf ("   [--key_upd REQ|ALL|RSP]\n");
  printf ("   [--slot <0~7|0xFF>]\n");
  printf ("   [--slot_count <1~8>]\n");
  printf ("   [--save_state <NegotiateStateFileName>]\n");
  printf ("   [--load_state <NegotiateStateFileName>]\n");
  printf ("   [--exe_mode SHUTDOWN|CONTINUE]\n");
  printf ("   [--exe_conn VER_ONLY|DIGEST|CERT|CHAL|MEAS]\n");
  printf ("   [--exe_session KEY_EX|PSK|NO_END|KEY_UPDATE|HEARTBEAT|MEAS]\n");
  printf ("   [--pcap <pcap_file_name>]\n");
  printf ("\n");
  printf ("NOTE:\n");
  printf ("   [--trans] is used to select transport layer message. By default, MCTP is used.\n");
  printf ("   [--ver] is version. By default, 1.1 is used.\n");
  printf ("   [--sec_ver] is secured message version. By default, 1.1 is used. 0 means no secured message version negotiation.\n");
  printf ("   [--cap] is capability flags. Multiple flags can be set together. Please use ',' for them.\n");
  printf ("           By default, CERT,CHAL,ENCRYPT,MAC,MUT_AUTH,KEY_EX,PSK,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR is used for Requester.\n");
  printf ("           By default, CACHE,CERT,CHAL,MEAS_SIG,MEAS_FRESH,ENCRYPT,MAC,MUT_AUTH,KEY_EX,PSK_WITH_CONTEXT,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR is used for Responder.\n");
  printf ("   [--hash] is hash algorithm. By default, SHA_384,SHA_256 is used.\n");
  printf ("   [--meas_spec] is measurement hash spec. By default, DMTF is used.\n");
  printf ("   [--meas_hash] is measurement hash algorithm. By default, SHA_512,SHA_384,SHA_256 is used.\n");
  printf ("   [--asym] is asym algorithm. By default, ECDSA_P384,ECDSA_P256 is used.\n");
  printf ("   [--req_asym] is requester asym algorithm. By default, RSAPSS_3072,RSAPSS_2048,RSASSA_3072,RSASSA_2048 is used.\n");
  printf ("   [--dhe] is DHE algorithm. By default, SECP_384_R1,SECP_256_R1,FFDHE_3072,FFDHE_2048 is used.\n");
  printf ("   [--aead] is AEAD algorithm. By default, AES_256_GCM,CHACHA20_POLY1305 is used.\n");
  printf ("   [--key_schedule] is key schedule algorithm. By default, HMAC_HASH is used.\n");
  printf ("   [--pqc_sig] is PQC sigature algorithm. By default, FALCON_1024,SPHINCS_{HARAKA,SHA256,SHAKE256}_128F_ROBUST is used.\n");
  printf ("   [--pqc_req_sig] is PQC requester sigature algorithm. By default, FALCON_512 is used.\n");
  printf ("   [--pqc_kem] is PQC key exchange algorithm. By default, KYBER_512,FRODOKEM_640_AES is used.\n");
  printf ("           Above algorithms also support multiple flags. Please use ',' for them.\n");
  printf ("           SHA3 is not supported so far.\n");
  printf ("           For pqc CERT mode, only a limited set of hybrid algorithm can be used. Please refer to readme.\n");
  printf ("   [--pqc_pub_key_mode] RAW means separated binary public key. CERT means hybrid X509 certificate. By default, RAW is used.\n");
  printf ("   [--basic_mut_auth] is the basic mutual authentication policy. BASIC is used in CHALLENGE_AUTH. By default, BASIC is used.\n");
  printf ("   [--mut_auth] is the mutual authentication policy. WO_ENCAP, W_ENCAP or DIGESTS is used in KEY_EXCHANGE_RSP. By default, W_ENCAP is used.\n");
  printf ("   [--meas_sum] is the measurment summary hash type in CHALLENGE_AUTH, KEY_EXCHANGE_RSP and PSK_EXCHANGE_RSP. By default, ALL is used.\n");
  printf ("   [--meas_op] is the measurement operation in GET_MEASUREMEMT. By default, ONE_BY_ONE is used.\n");
  printf ("   [--key_upd] is the key update operation in KEY_UPDATE. By default, ALL is used. RSP will trigger encapsulated KEY_UPDATE.\n");
  printf ("   [--slot_id] is to select the peer slot ID in GET_MEASUREMENT, CHALLENGE_AUTH, KEY_EXCHANGE and FINISH. By default, 0 is used.\n");
  printf ("           0xFF can be used to indicate provisioned certificate chain. No GET_CERTIFICATE is needed.\n");
  printf ("           0xFF must be used to if PUB_KEY_ID is set. No GET_DIGEST/GET_CERTIFICATE is sent.\n");
  printf ("   [--slot_count] is to select the local slot count. By default, 3 is used.\n");
  printf ("   [--save_state] is to save the current negotiated state to a write-only file.\n");
  printf ("           The requester and responder will save state after GET_VERSION/GET_CAPABILLITIES/NEGOTIATE_ALGORITHMS.\n");
  printf ("           (negotiated state == ver|cap|hash|meas_spec|meas_hash|asym|req_asym|dhe|aead|key_schedule)\n");
  printf ("           The responder should set CACHE capabilities, otherwise the state will not be saved.\n");
  printf ("           The requester will clear PRESERVE_NEGOTIATED_STATE_CLEAR bit in END_SESSION to preserve, otherwise this bit is set.\n");
  printf ("           The responder will save empty state, if the requester sets PRESERVE_NEGOTIATED_STATE_CLEAR bit in END_SESSION.\n");
  printf ("   [--load_state] is to load the negotiated state to current session from a read-only file.\n");
  printf ("           The requester and responder will provision the state just after SPDM context is created.\n");
  printf ("           The user need guarantee the state file is gnerated correctly.\n");
  printf ("           The command line input - ver|cap|hash|meas_spec|meas_hash|asym|req_asym|dhe|aead|key_schedule are ignored.\n");
  printf ("           The requester will skip GET_VERSION/GET_CAPABILLITIES/NEGOTIATE_ALGORITHMS.\n");
  printf ("   [--exe_mode] is used to control the execution mode. By default, it is SHUTDOWN.\n");
  printf ("           SHUTDOWN means the requester asks the responder to stop.\n");
  printf ("           CONTINUE means the requester asks the responder to preserve the current SPDM context.\n");
  printf ("   [--exe_conn] is used to control the SPDM connection. By default, it is DIGEST,CERT,CHAL,MEAS.\n");
  printf ("           VER_ONLY means REQUESTER does not send GET_CAPABILITIES/NEGOTIATE_ALGORITHMS. It is used for quick symmetric authentication with PSK.\n");
  printf ("           DIGEST means send GET_DIGESTS command.\n");
  printf ("           CERT means send GET_CERTIFICATE command.\n");
  printf ("           CHAL means send CHALLENGE command.\n");
  printf ("           MEAS means send GET_MEASUREMENT command.\n");
  printf ("   [--exe_session] is used to control the SPDM session. By default, it is KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS.\n");
  printf ("           KEY_EX means to setup KEY_EXCHANGE session.\n");
  printf ("           PSK means to setup PSK_EXCHANGE session.\n");
  printf ("           NO_END means to not send END_SESSION.\n");
  printf ("           KEY_UPDATE means to send KEY_UPDATE in session.\n");
  printf ("           HEARTBEAT means to send HEARTBEAT in session.\n");
  printf ("           MEAS means send GET_MEASUREMENT command in session.\n");
  printf ("   [--pcap] is used to generate PCAP dump file for offline analysis.\n");
  fprintf (stdout, "\n");
}

typedef struct {
  uint32  value;
  char8   *name;
} value_string_entry_t;

value_string_entry_t  m_transport_value_string_table[] = {
  {SOCKET_TRANSPORT_TYPE_MCTP,    "MCTP"},
  {SOCKET_TRANSPORT_TYPE_PCI_DOE, "PCI_DOE"},
};

value_string_entry_t  m_version_value_string_table[] = {
  {SPDM_MESSAGE_VERSION_10,  "1.0"},
  {SPDM_MESSAGE_VERSION_11,  "1.1"},
};

value_string_entry_t  m_secured_message_version_value_string_table[] = {
  {0,                        "0"},
  {SPDM_MESSAGE_VERSION_11,  "1.1"},
};

value_string_entry_t  m_spdm_requester_capabilities_string_table[] = {
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP,                   "CERT"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP,                   "CHAL"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP,                "ENCRYPT"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP,                    "MAC"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,               "MUT_AUTH"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,                 "KEY_EX"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER,          "PSK"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP,                  "ENCAP"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP,                  "HBEAT"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP,                "KEY_UPD"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP, "HANDSHAKE_IN_CLEAR"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP,             "PUB_KEY_ID"},
};

value_string_entry_t  m_spdm_responder_capabilities_string_table[] = {
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP,                      "CACHE"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP,                       "CERT"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP,                       "CHAL"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG,                "MEAS_NO_SIG"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG,                   "MEAS_SIG"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP,                 "MEAS_FRESH"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP,                    "ENCRYPT"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP,                        "MAC"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP,                   "MUT_AUTH"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP,                     "KEY_EX"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER,              "PSK"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT, "PSK_WITH_CONTEXT"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP,                      "ENCAP"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP,                      "HBEAT"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP,                    "KEY_UPD"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,     "HANDSHAKE_IN_CLEAR"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP,                 "PUB_KEY_ID"},
};

value_string_entry_t  m_hash_value_string_table[] = {
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,  "SHA_256"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,  "SHA_384"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,  "SHA_512"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512"},
};

value_string_entry_t  m_measurement_spec_value_string_table[] = {
  {SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,        "DMTF"},
};

value_string_entry_t  m_measurement_hash_value_string_table[] = {
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,  "RAW_BIT"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,      "SHA_256"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,      "SHA_384"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,      "SHA_512"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256,     "SHA3_256"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384,     "SHA3_384"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512,     "SHA3_512"},
};

value_string_entry_t  m_asym_value_string_table[] = {
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,          "RSASSA_2048"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,          "RSASSA_3072"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,          "RSASSA_4096"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,          "RSAPSS_2048"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,          "RSAPSS_3072"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,          "RSAPSS_4096"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,  "ECDSA_P256"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,  "ECDSA_P384"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,  "ECDSA_P521"},
};

value_string_entry_t  m_dhe_value_string_table[] = {
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,  "FFDHE_2048"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,  "FFDHE_3072"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,  "FFDHE_4096"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1, "SECP_256_R1"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1, "SECP_384_R1"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1, "SECP_521_R1"},
};

value_string_entry_t  m_aead_value_string_table[] = {
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,        "AES_128_GCM"},
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,        "AES_256_GCM"},
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,  "CHACHA20_POLY1305"},
};

value_string_entry_t  m_key_schedule_value_string_table[] = {
  {SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH,        "HMAC_HASH"},
};

value_string_entry_t  m_pqc_sig_value_string_table[] = {
  {PQC_CRYPTO_SIG_NID_DILITHIUM_2,                 "DILITHIUM_2"},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_3,                 "DILITHIUM_3"},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_5,                 "DILITHIUM_5"},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_2_AES,             "DILITHIUM_2_AES"},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_3_AES,             "DILITHIUM_3_AES"},
  {PQC_CRYPTO_SIG_NID_DILITHIUM_5_AES,             "DILITHIUM_5_AES"},

  {PQC_CRYPTO_SIG_NID_FALCON_512,                  "FALCON_512"},
  {PQC_CRYPTO_SIG_NID_FALCON_1024,                 "FALCON_1024"},

  {PQC_CRYPTO_SIG_NID_RAINBOW_I_CLASSIC,           "RAINBOW_I_CLASSIC"},
  {PQC_CRYPTO_SIG_NID_RAINBOW_I_CIRCUMZENITHAL,    "RAINBOW_I_CIRCUMZENITHAL"},
  {PQC_CRYPTO_SIG_NID_RAINBOW_I_COMPRESSED,        "RAINBOW_I_COMPRESSED"},
  {PQC_CRYPTO_SIG_NID_RAINBOW_III_CLASSIC,         "RAINBOW_III_CLASSIC"},
  {PQC_CRYPTO_SIG_NID_RAINBOW_III_CIRCUMZENITHAL,  "RAINBOW_III_CIRCUMZENITHAL"},
  {PQC_CRYPTO_SIG_NID_RAINBOW_III_COMPRESSED,      "RAINBOW_III_COMPRESSED"},
  {PQC_CRYPTO_SIG_NID_RAINBOW_V_CLASSIC,           "RAINBOW_V_CLASSIC"},
  {PQC_CRYPTO_SIG_NID_RAINBOW_V_CIRCUMZENITHAL,    "RAINBOW_V_CIRCUMZENITHAL"},
  {PQC_CRYPTO_SIG_NID_RAINBOW_V_COMPRESSED,        "RAINBOW_V_COMPRESSED"},

  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_ROBUST,  "SPHINCS_HARAKA_128F_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_SIMPLE,  "SPHINCS_HARAKA_128F_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_ROBUST,  "SPHINCS_HARAKA_128S_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_SIMPLE,  "SPHINCS_HARAKA_128S_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_ROBUST,  "SPHINCS_HARAKA_192F_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_SIMPLE,  "SPHINCS_HARAKA_192F_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_ROBUST,  "SPHINCS_HARAKA_192S_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_SIMPLE,  "SPHINCS_HARAKA_192S_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_ROBUST,  "SPHINCS_HARAKA_256F_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_SIMPLE,  "SPHINCS_HARAKA_256F_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_ROBUST,  "SPHINCS_HARAKA_256S_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_SIMPLE,  "SPHINCS_HARAKA_256S_SIMPLE"},

  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_ROBUST,  "SPHINCS_SHA256_128F_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_SIMPLE,  "SPHINCS_SHA256_128F_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_ROBUST,  "SPHINCS_SHA256_128S_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_SIMPLE,  "SPHINCS_SHA256_128S_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_ROBUST,  "SPHINCS_SHA256_192F_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_SIMPLE,  "SPHINCS_SHA256_192F_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_ROBUST,  "SPHINCS_SHA256_192S_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_SIMPLE,  "SPHINCS_SHA256_192S_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_ROBUST,  "SPHINCS_SHA256_256F_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_SIMPLE,  "SPHINCS_SHA256_256F_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_ROBUST,  "SPHINCS_SHA256_256S_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_SIMPLE,  "SPHINCS_SHA256_256S_SIMPLE"},

  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_ROBUST,  "SPHINCS_SHAKE256_128F_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_SIMPLE,  "SPHINCS_SHAKE256_128F_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_ROBUST,  "SPHINCS_SHAKE256_128S_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_SIMPLE,  "SPHINCS_SHAKE256_128S_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_ROBUST,  "SPHINCS_SHAKE256_192F_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_SIMPLE,  "SPHINCS_SHAKE256_192F_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_ROBUST,  "SPHINCS_SHAKE256_192S_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_SIMPLE,  "SPHINCS_SHAKE256_192S_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_ROBUST,  "SPHINCS_SHAKE256_256F_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_SIMPLE,  "SPHINCS_SHAKE256_256F_SIMPLE"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_ROBUST,  "SPHINCS_SHAKE256_256S_ROBUST"},
  {PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_SIMPLE,  "SPHINCS_SHAKE256_256S_SIMPLE"},

  {PQC_CRYPTO_SIG_NID_PICNIC_L1_FS,                "PICNIC_L1_FS"},
  {PQC_CRYPTO_SIG_NID_PICNIC_L1_UR,                "PICNIC_L1_UR"},
  {PQC_CRYPTO_SIG_NID_PICNIC_L1_FULL,              "PICNIC_L1_FULL"},
  {PQC_CRYPTO_SIG_NID_PICNIC_L3_FS,                "PICNIC_L3_FS"},
  {PQC_CRYPTO_SIG_NID_PICNIC_L3_UR,                "PICNIC_L3_UR"},
  {PQC_CRYPTO_SIG_NID_PICNIC_L3_FULL,              "PICNIC_L3_FULL"},
  {PQC_CRYPTO_SIG_NID_PICNIC_L5_FS,                "PICNIC_L5_FS"},
  {PQC_CRYPTO_SIG_NID_PICNIC_L5_UR,                "PICNIC_L5_UR"},
  {PQC_CRYPTO_SIG_NID_PICNIC_L5_FULL,              "PICNIC_L5_FULL"},
  {PQC_CRYPTO_SIG_NID_PICNIC3_L1,                  "PICNIC3_L1"},
  {PQC_CRYPTO_SIG_NID_PICNIC3_L3,                  "PICNIC3_L3"},
  {PQC_CRYPTO_SIG_NID_PICNIC3_L5,                  "PICNIC3_L5"},
};

value_string_entry_t  m_pqc_kem_value_string_table[] = {
  {PQC_CRYPTO_KEM_NID_BIKE1_L1_CPA,                 "BIKE1_L1_CPA"},
  {PQC_CRYPTO_KEM_NID_BIKE1_L3_CPA,                 "BIKE1_L3_CPA"},
  {PQC_CRYPTO_KEM_NID_BIKE1_L1_FO,                  "BIKE1_L1_FO"},
  {PQC_CRYPTO_KEM_NID_BIKE1_L3_FO,                  "BIKE1_L3_FO"},

  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864,      "CLASSIC_MCELIECE_348864"},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864F,     "CLASSIC_MCELIECE_348864F"},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896,      "CLASSIC_MCELIECE_460896"},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896F,     "CLASSIC_MCELIECE_460896F"},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128,     "CLASSIC_MCELIECE_6688128"},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128F,    "CLASSIC_MCELIECE_6688128F"},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119,     "CLASSIC_MCELIECE_6960119"},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119F,    "CLASSIC_MCELIECE_6960119F"},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128,     "CLASSIC_MCELIECE_8192128"},
  {PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128F,    "CLASSIC_MCELIECE_8192128F"},

  {PQC_CRYPTO_KEM_NID_HQC_128,                      "HQC_128"},
  {PQC_CRYPTO_KEM_NID_HQC_192,                      "HQC_192"},
  {PQC_CRYPTO_KEM_NID_HQC_256,                      "HQC_256"},

  {PQC_CRYPTO_KEM_NID_KYBER_512,                    "KYBER_512"},
  {PQC_CRYPTO_KEM_NID_KYBER_768,                    "KYBER_768"},
  {PQC_CRYPTO_KEM_NID_KYBER_1024,                   "KYBER_1024"},
  {PQC_CRYPTO_KEM_NID_KYBER_512_90S,                "KYBER_512_90S"},
  {PQC_CRYPTO_KEM_NID_KYBER_768_90S,                "KYBER_768_90S"},
  {PQC_CRYPTO_KEM_NID_KYBER_1024_90S,               "KYBER_1024_90S"},

  {PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_509,            "NTRU_HPS_2048_509"},
  {PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_677,            "NTRU_HPS_2048_677"},
  {PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_821,            "NTRU_HPS_2048_821"},
  {PQC_CRYPTO_KEM_NID_NTRU_HRSS_701,                "NTRU_HRSS_701"},

  {PQC_CRYPTO_KEM_NID_NTRULPR653,                   "NTRULPR653"},
  {PQC_CRYPTO_KEM_NID_NTRULPR761,                   "NTRULPR761"},
  {PQC_CRYPTO_KEM_NID_NTRULPR857,                   "NTRULPR857"},
  {PQC_CRYPTO_KEM_NID_SNTRUP653,                    "SNTRUP653"},
  {PQC_CRYPTO_KEM_NID_SNTRUP761,                    "SNTRUP761"},
  {PQC_CRYPTO_KEM_NID_SNTRUP857,                    "SNTRUP857"},

  {PQC_CRYPTO_KEM_NID_LIGHTSABER_KEM,               "LIGHTSABER_KEM"},
  {PQC_CRYPTO_KEM_NID_SABER_KEM,                    "SABER_KEM"},
  {PQC_CRYPTO_KEM_NID_FIRESABER_KEM,                "FIRESABER_KEM"},

  {PQC_CRYPTO_KEM_NID_FRODOKEM_640_AES,             "FRODOKEM_640_AES"},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_640_SHAKE,           "FRODOKEM_640_SHAKE"},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_976_AES,             "FRODOKEM_976_AES"},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_976_SHAKE,           "FRODOKEM_976_SHAKE"},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_1344_AES,            "FRODOKEM_1344_AES"},
  {PQC_CRYPTO_KEM_NID_FRODOKEM_1344_SHAKE,          "FRODOKEM_1344_SHAKE"},

  {PQC_CRYPTO_KEM_NID_SIDH_P434,                    "SIDH_P434"},
  {PQC_CRYPTO_KEM_NID_SIDH_P434_COMPRESSED,         "SIDH_P434_COMPRESSED"},
  {PQC_CRYPTO_KEM_NID_SIDH_P503,                    "SIDH_P503"},
  {PQC_CRYPTO_KEM_NID_SIDH_P503_COMPRESSED,         "SIDH_P503_COMPRESSED"},
  {PQC_CRYPTO_KEM_NID_SIDH_P610,                    "SIDH_P610"},
  {PQC_CRYPTO_KEM_NID_SIDH_P610_COMPRESSED,         "SIDH_P610_COMPRESSED"},
  {PQC_CRYPTO_KEM_NID_SIDH_P751,                    "SIDH_P751"},
  {PQC_CRYPTO_KEM_NID_SIDH_P751_COMPRESSED,         "SIDH_P751_COMPRESSED"},
  {PQC_CRYPTO_KEM_NID_SIKE_P434,                    "SIKE_P434"},
  {PQC_CRYPTO_KEM_NID_SIKE_P434_COMPRESSED,         "SIKE_P434_COMPRESSED"},
  {PQC_CRYPTO_KEM_NID_SIKE_P503,                    "SIKE_P503"},
  {PQC_CRYPTO_KEM_NID_SIKE_P503_COMPRESSED,         "SIKE_P503_COMPRESSED"},
  {PQC_CRYPTO_KEM_NID_SIKE_P610,                    "SIKE_P610"},
  {PQC_CRYPTO_KEM_NID_SIKE_P610_COMPRESSED,         "SIKE_P610_COMPRESSED"},
  {PQC_CRYPTO_KEM_NID_SIKE_P751,                    "SIKE_P751"},
  {PQC_CRYPTO_KEM_NID_SIKE_P751_COMPRESSED,         "SIKE_P751_COMPRESSED"},
};

value_string_entry_t  m_pqc_pub_key_mode_string_table[] = {
  {SPDM_DATA_PUBLIC_KEY_MODE_RAW,    "RAW"},
  {SPDM_DATA_PUBLIC_KEY_MODE_CERT,   "CERT"},
};

value_string_entry_t  m_basic_mut_auth_policy_string_table[] = {
  {0,                                                                "NO"},
  {1,                                                                "BASIC"},
};

value_string_entry_t  m_mut_auth_policy_string_table[] = {
  {0,                                                                "NO"},
  {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED,                    "WO_ENCAP"},
  {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST, "W_ENCAP"},
  {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS,   "DIGESTS"},
};

value_string_entry_t  m_measurement_summary_hash_type_string_table[] = {
  {SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,    "NO"},
  {SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, "TCB"},
  {SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH,          "ALL"},
};

value_string_entry_t  m_measurement_operation_string_table[] = {
  {SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS, "ONE_BY_ONE"},
  {SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,              "ALL"},
};

value_string_entry_t  m_key_update_action_string_table[] = {
  {SPDM_KEY_UPDATE_ACTION_REQUESTER,  "REQ"},
  {SPDM_KEY_UPDATE_ACTION_RESPONDER,  "RSP"},
  {SPDM_KEY_UPDATE_ACTION_ALL,        "ALL"},
};

value_string_entry_t  m_slot_id_string_table[] = {
  {0x0, "0"},
  {0x1, "1"},
  {0x2, "2"},
  {0x3, "3"},
  {0x4, "4"},
  {0x5, "5"},
  {0x6, "6"},
  {0x7, "7"},
  {0xFF, "0xFF"},
};

value_string_entry_t  m_slot_count_string_table[] = {
  {0x1, "1"},
  {0x2, "2"},
  {0x3, "3"},
  {0x4, "4"},
  {0x5, "5"},
  {0x6, "6"},
  {0x7, "7"},
  {0x8, "8"},
};

value_string_entry_t  m_exe_mode_string_table[] = {
  {EXE_MODE_SHUTDOWN, "SHUTDOWN"},
  {EXE_MODE_CONTINUE, "CONTINUE"},
};

value_string_entry_t  m_exe_connection_string_table[] = {
  {EXE_CONNECTION_VERSION_ONLY,    "VER_ONLY"},
  {EXE_CONNECTION_DIGEST,          "DIGEST"},
  {EXE_CONNECTION_CERT,            "CERT"},
  {EXE_CONNECTION_CHAL,            "CHAL"},
  {EXE_CONNECTION_MEAS,            "MEAS"},
};

value_string_entry_t  m_exe_session_string_table[] = {
  {EXE_SESSION_KEY_EX,     "KEY_EX"},
  {EXE_SESSION_PSK,        "PSK"},
  {EXE_SESSION_NO_END,     "NO_END"},
  {EXE_SESSION_KEY_UPDATE, "KEY_UPDATE"},
  {EXE_SESSION_HEARTBEAT,  "HEARTBEAT"},
  {EXE_SESSION_MEAS,       "MEAS"},
};

boolean
get_value_from_name (
  IN value_string_entry_t  *table,
  IN uintn               entry_count,
  IN char8               *name,
  OUT uint32             *value
  )
{
  uintn  index;

  for (index = 0; index < entry_count; index++) {
    if (strcmp (name, table[index].name) == 0) {
      *value = table[index].value;
      return TRUE;
    }
  }
  return FALSE;
}

boolean
get_flags_from_name (
  IN value_string_entry_t  *table,
  IN uintn               entry_count,
  IN char8               *name,
  OUT uint32             *flags
  )
{
  uint32  value;
  char8   *flag_name;
  char8   *local_name;
  boolean ret;

  local_name = (void *)malloc (strlen(name) + 1);
  if (local_name == NULL) {
    return FALSE;
  }
  strcpy (local_name, name);

  //
  // name = Flag1,Flag2,...,FlagN
  //
  *flags = 0;
  flag_name = strtok (local_name, ",");
  while (flag_name != NULL) {
    if (!get_value_from_name (table, entry_count, flag_name, &value)) {
      printf ("unsupported flag - %s\n", flag_name);
      ret = FALSE;
      goto done;
    }
    *flags |= value;
    flag_name = strtok (NULL, ",");
  }
  if (*flags == 0) {
    ret = FALSE;
  } else {
    ret = TRUE;
  }
done:
  free (local_name);
  return ret;
}

boolean
get_pqc_algo_flags_from_name (
  IN value_string_entry_t  *table,
  IN uintn               entry_count,
  IN char8               *name,
  OUT pqc_algo_t         pqc_algo_flags
  )
{
  uint32  value;
  char8   *flag_name;
  char8   *local_name;
  boolean ret;
  pqc_algo_t  this_pqc_algo;

  local_name = (void *)malloc (strlen(name) + 1);
  if (local_name == NULL) {
    return FALSE;
  }
  strcpy (local_name, name);

  //
  // name = Flag1,Flag2,...,FlagN
  //
  zero_mem (pqc_algo_flags, sizeof(pqc_algo_t));
  flag_name = strtok (local_name, ",");
  while (flag_name != NULL) {
    if (!get_value_from_name (table, entry_count, flag_name, &value)) {
      printf ("unsupported flag - %s\n", flag_name);
      ret = FALSE;
      goto done;
    }
    spdm_get_pqc_algo_from_nid (value, this_pqc_algo);
    spdm_pqc_algo_or (pqc_algo_flags, this_pqc_algo, pqc_algo_flags);
    flag_name = strtok (NULL, ",");
  }
  if (spdm_pqc_algo_is_zero (pqc_algo_flags)) {
    ret = FALSE;
  } else {
    ret = TRUE;
  }
done:
  free (local_name);
  return ret;
}

void
process_args (
  char  *program_name,
  int   argc,
  char  *argv[ ]
  )
{
  uint32  data32;
  char8   *pcap_file_name;

  pcap_file_name = NULL;

  if (argc == 1) {
    return ;
  }

  argc --;
  argv ++;

  if ((strcmp (argv[0], "-h") == 0) ||
      (strcmp (argv[0], "--help") == 0)) {
    print_usage (program_name);
    exit (0);
  }

  while (argc > 0) {
    if (strcmp (argv[0], "--trans") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_transport_value_string_table, ARRAY_SIZE(m_transport_value_string_table), argv[1], &m_use_transport_layer)) {
          printf ("invalid --trans %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("trans - 0x%x\n", m_use_transport_layer);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --trans\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--ver") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_version_value_string_table, ARRAY_SIZE(m_version_value_string_table), argv[1], &data32)) {
          printf ("invalid --ver %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_use_version = (uint8)data32;
        printf ("ver - 0x%02x\n", m_use_version);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --ver\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--sec_ver") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_secured_message_version_value_string_table, ARRAY_SIZE(m_secured_message_version_value_string_table), argv[1], &data32)) {
          printf ("invalid --sec_ver %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_use_secured_message_version = (uint8)data32;
        printf ("sec_ver - 0x%02x\n", m_use_secured_message_version);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --sec_ver\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--cap") == 0) {
      if (argc >= 2) {
        value_string_entry_t  *CapabilitiesStringTable;
        uintn               count;

        if (strcmp (program_name, "spdm_requester_emu") == 0) {
          CapabilitiesStringTable = m_spdm_requester_capabilities_string_table;
          count = ARRAY_SIZE(m_spdm_requester_capabilities_string_table);
        } else if (strcmp (program_name, "spdm_responder_emu") == 0) {
          CapabilitiesStringTable = m_spdm_responder_capabilities_string_table;
          count = ARRAY_SIZE(m_spdm_responder_capabilities_string_table);
        } else {
          ASSERT (FALSE);
          printf ("unsupported --cap\n");
          print_usage (program_name);
          exit (0);
        }
        if (!get_flags_from_name (CapabilitiesStringTable, count, argv[1], &m_use_capability_flags)) {
          printf ("invalid --cap %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("cap - 0x%08x\n", m_use_capability_flags);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --cap\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--hash") == 0) {
      if (argc >= 2) {
        if (!get_flags_from_name (m_hash_value_string_table, ARRAY_SIZE(m_hash_value_string_table), argv[1], &m_support_hash_algo)) {
          printf ("invalid --hash %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("hash - 0x%08x\n", m_support_hash_algo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --hash\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--meas_spec") == 0) {
      if (argc >= 2) {
        if (!get_flags_from_name (m_measurement_spec_value_string_table, ARRAY_SIZE(m_measurement_spec_value_string_table), argv[1], &data32)) {
          printf ("invalid --meas_spec %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_support_measurement_spec = (uint8)data32;
        printf ("meas_spec - 0x%02x\n", m_support_measurement_spec);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --meas_spec\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--meas_hash") == 0) {
      if (argc >= 2) {
        if (!get_flags_from_name (m_measurement_hash_value_string_table, ARRAY_SIZE(m_measurement_hash_value_string_table), argv[1], &m_support_measurement_hash_algo)) {
          printf ("invalid --meas_hash %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("meas_hash - 0x%08x\n", m_support_measurement_hash_algo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --meas_hash\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--asym") == 0) {
      if (argc >= 2) {
        if (!get_flags_from_name (m_asym_value_string_table, ARRAY_SIZE(m_asym_value_string_table), argv[1], &m_support_asym_algo)) {
          printf ("invalid --asym %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("asym - 0x%08x\n", m_support_asym_algo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --asym\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--req_asym") == 0) {
      if (argc >= 2) {
        if (!get_flags_from_name (m_asym_value_string_table, ARRAY_SIZE(m_asym_value_string_table), argv[1], &data32)) {
          printf ("invalid --req_asym %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_support_req_asym_algo = (uint16)data32;
        printf ("req_asym - 0x%04x\n", m_support_req_asym_algo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --req_asym\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--dhe") == 0) {
      if (argc >= 2) {
        if (!get_flags_from_name (m_dhe_value_string_table, ARRAY_SIZE(m_dhe_value_string_table), argv[1], &data32)) {
          printf ("invalid --dhe %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_support_dhe_algo = (uint16)data32;
        printf ("dhe - 0x%04x\n", m_support_dhe_algo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --dhe\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--aead") == 0) {
      if (argc >= 2) {
        if (!get_flags_from_name (m_aead_value_string_table, ARRAY_SIZE(m_aead_value_string_table), argv[1], &data32)) {
          printf ("invalid --aead %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_support_aead_algo = (uint16)data32;
        printf ("aead - 0x%04x\n", m_support_aead_algo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --aead\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--key_schedule") == 0) {
      if (argc >= 2) {
        if (!get_flags_from_name (m_key_schedule_value_string_table, ARRAY_SIZE(m_key_schedule_value_string_table), argv[1], &data32)) {
          printf ("invalid --key_schedule %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_support_key_schedule_algo = (uint16)data32;
        printf ("key_schedule - 0x%04x\n", m_support_key_schedule_algo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --key_schedule\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--pqc_sig") == 0) {
      if (argc >= 2) {
        if (!get_pqc_algo_flags_from_name (m_pqc_sig_value_string_table, ARRAY_SIZE(m_pqc_sig_value_string_table), argv[1], m_support_pqc_sig_algo)) {
          printf ("invalid --pqc_sig %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("pqc_sig - ");
        dump_hex_str (m_support_pqc_sig_algo, sizeof(pqc_algo_t));
        printf ("\n");
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --pqc_sig\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--pqc_req_sig") == 0) {
      if (argc >= 2) {
        if (!get_pqc_algo_flags_from_name (m_pqc_sig_value_string_table, ARRAY_SIZE(m_pqc_sig_value_string_table), argv[1], m_support_pqc_req_sig_algo)) {
          printf ("invalid --pqc_req_sig %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("pqc_req_sig - ");
        dump_hex_str (m_support_pqc_req_sig_algo, sizeof(pqc_algo_t));
        printf ("\n");
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --pqc_req_sig\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--pqc_kem") == 0) {
      if (argc >= 2) {
        if (!get_pqc_algo_flags_from_name (m_pqc_kem_value_string_table, ARRAY_SIZE(m_pqc_kem_value_string_table), argv[1], m_support_pqc_kem_algo)) {
          printf ("invalid --pqc_kem %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("pqc_kem - ");
        dump_hex_str (m_support_pqc_kem_algo, sizeof(pqc_algo_t));
        printf ("\n");
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --pqc_kem\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--pqc_pub_key_mode") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_pqc_pub_key_mode_string_table, ARRAY_SIZE(m_pqc_pub_key_mode_string_table), argv[1], &m_pqc_pub_key_mode)) {
          printf ("invalid --pqc_pub_key_mode %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("pqc_pub_key_mode - 0x%08x\n", m_pqc_pub_key_mode);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --pqc_pub_key_mode\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--basic_mut_auth") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_basic_mut_auth_policy_string_table, ARRAY_SIZE(m_basic_mut_auth_policy_string_table), argv[1], &data32)) {
          printf ("invalid --basic_mut_auth %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_use_basic_mut_auth = (uint8)data32;
        printf ("basic_mut_auth - 0x%02x\n", m_use_basic_mut_auth);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --basic_mut_auth\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--mut_auth") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_mut_auth_policy_string_table, ARRAY_SIZE(m_mut_auth_policy_string_table), argv[1], &data32)) {
          printf ("invalid --mut_auth %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_use_mut_auth = (uint8)data32;
        printf ("mut_auth - 0x%02x\n", m_use_mut_auth);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --mut_auth\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--meas_sum") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_measurement_summary_hash_type_string_table, ARRAY_SIZE(m_measurement_summary_hash_type_string_table), argv[1], &data32)) {
          printf ("invalid --meas_sum %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_use_measurement_summary_hash_type = (uint8)data32;
        printf ("meas_sum - 0x%02x\n", m_use_measurement_summary_hash_type);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --meas_sum\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--meas_op") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_measurement_operation_string_table, ARRAY_SIZE(m_measurement_operation_string_table), argv[1], &data32)) {
          printf ("invalid --meas_op %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_use_measurement_operation = (uint8)data32;
        printf ("meas_op - 0x%02x\n", m_use_measurement_operation);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --meas_op\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--key_upd") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_key_update_action_string_table, ARRAY_SIZE(m_key_update_action_string_table), argv[1], &data32)) {
          printf ("invalid --key_upd %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_use_key_update_action = data32;
        printf ("key_upd - 0x%08x\n", m_use_key_update_action);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --key_upd\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--slot_id") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_slot_id_string_table, ARRAY_SIZE(m_slot_id_string_table), argv[1], &data32)) {
          printf ("invalid --slot_id %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_use_slot_id = (uint8)data32;
        printf ("slot_id - 0x%02x\n", m_use_slot_id);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --slot_id\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--slot_count") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_slot_count_string_table, ARRAY_SIZE(m_slot_count_string_table), argv[1], &data32)) {
          printf ("invalid --slot_count %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        m_use_slot_count = (uint8)data32;
        printf ("slot_count - 0x%02x\n", m_use_slot_count);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --slot_count\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--save_state") == 0) {
      if (argc >= 2) {
        m_save_state_file_name = argv[1];
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --save_state\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--load_state") == 0) {
      if (argc >= 2) {
        m_load_state_file_name = argv[1];
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --load_state\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--exe_mode") == 0) {
      if (argc >= 2) {
        if (!get_value_from_name (m_exe_mode_string_table, ARRAY_SIZE(m_exe_mode_string_table), argv[1], &m_exe_mode)) {
          printf ("invalid --exe_mode %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("exe_mode - 0x%08x\n", m_exe_mode);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --exe_mode\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--exe_conn") == 0) {
      if (argc >= 2) {
        if (!get_flags_from_name (m_exe_connection_string_table, ARRAY_SIZE(m_exe_connection_string_table), argv[1], &m_exe_connection)) {
          printf ("invalid --exe_conn %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("exe_conn - 0x%08x\n", m_exe_connection);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --exe_conn\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--exe_session") == 0) {
      if (argc >= 2) {
        if (!get_flags_from_name (m_exe_session_string_table, ARRAY_SIZE(m_exe_session_string_table), argv[1], &m_exe_session)) {
          printf ("invalid --exe_session %s\n", argv[1]);
          print_usage (program_name);
          exit (0);
        }
        printf ("exe_session - 0x%08x\n", m_exe_session);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --exe_session\n");
        print_usage (program_name);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--pcap") == 0) {
      if (argc >= 2) {
        pcap_file_name = argv[1];
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --pcap\n");
        print_usage (program_name);
        exit (0);
      }
    }

    printf ("invalid %s\n", argv[0]);
    print_usage (program_name);
    exit (0);
  }

  //
  // Open PCAP file as last option, after the user indicates transport type.
  //
  if (pcap_file_name != NULL) {
    if (!open_pcap_packet_file (pcap_file_name)) {
      print_usage (program_name);
      exit (0);
    }
  }

  return ;
}
