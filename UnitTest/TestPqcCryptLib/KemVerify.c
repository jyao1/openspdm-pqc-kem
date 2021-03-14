/** @file
  Application for OQS-KEM Primitives Validation.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PqcCryptest.h"

/*
UEFI-OQS KEM Testing:
NID: 0x20300, PubKeySize: 2249, PrivKeySize: 2289, CipherTextSize: 4481, SharedKeySize: 64
NID: 0x20301, PubKeySize: 4522, PrivKeySize: 4562, CipherTextSize: 9026, SharedKeySize: 64
NID: 0x20302, PubKeySize: 7245, PrivKeySize: 7285, CipherTextSize: 14469, SharedKeySize: 64
NID: 0x20400, PubKeySize: 800, PrivKeySize: 1632, CipherTextSize: 768, SharedKeySize: 32
NID: 0x20401, PubKeySize: 1184, PrivKeySize: 2400, CipherTextSize: 1088, SharedKeySize: 32
NID: 0x20402, PubKeySize: 1568, PrivKeySize: 3168, CipherTextSize: 1568, SharedKeySize: 32
NID: 0x20403, PubKeySize: 800, PrivKeySize: 1632, CipherTextSize: 768, SharedKeySize: 32
NID: 0x20404, PubKeySize: 1184, PrivKeySize: 2400, CipherTextSize: 1088, SharedKeySize: 32
NID: 0x20405, PubKeySize: 1568, PrivKeySize: 3168, CipherTextSize: 1568, SharedKeySize: 32
NID: 0x20500, PubKeySize: 699, PrivKeySize: 935, CipherTextSize: 699, SharedKeySize: 32
NID: 0x20501, PubKeySize: 930, PrivKeySize: 1234, CipherTextSize: 930, SharedKeySize: 32
NID: 0x20502, PubKeySize: 1230, PrivKeySize: 1590, CipherTextSize: 1230, SharedKeySize: 32
NID: 0x20503, PubKeySize: 1138, PrivKeySize: 1450, CipherTextSize: 1138, SharedKeySize: 32
NID: 0x20600, PubKeySize: 897, PrivKeySize: 1125, CipherTextSize: 1025, SharedKeySize: 32
NID: 0x20601, PubKeySize: 1039, PrivKeySize: 1294, CipherTextSize: 1167, SharedKeySize: 32
NID: 0x20602, PubKeySize: 1184, PrivKeySize: 1463, CipherTextSize: 1312, SharedKeySize: 32
NID: 0x20603, PubKeySize: 994, PrivKeySize: 1518, CipherTextSize: 897, SharedKeySize: 32
NID: 0x20604, PubKeySize: 1158, PrivKeySize: 1763, CipherTextSize: 1039, SharedKeySize: 32
NID: 0x20605, PubKeySize: 1322, PrivKeySize: 1999, CipherTextSize: 1184, SharedKeySize: 32
NID: 0x20700, PubKeySize: 672, PrivKeySize: 1568, CipherTextSize: 736, SharedKeySize: 32
NID: 0x20701, PubKeySize: 992, PrivKeySize: 2304, CipherTextSize: 1088, SharedKeySize: 32
NID: 0x20702, PubKeySize: 1312, PrivKeySize: 3040, CipherTextSize: 1472, SharedKeySize: 32
NID: 0x20800, PubKeySize: 9616, PrivKeySize: 19888, CipherTextSize: 9720, SharedKeySize: 16
NID: 0x20801, PubKeySize: 9616, PrivKeySize: 19888, CipherTextSize: 9720, SharedKeySize: 16
NID: 0x20802, PubKeySize: 15632, PrivKeySize: 31296, CipherTextSize: 15744, SharedKeySize: 24
NID: 0x20803, PubKeySize: 15632, PrivKeySize: 31296, CipherTextSize: 15744, SharedKeySize: 24
NID: 0x20804, PubKeySize: 21520, PrivKeySize: 43088, CipherTextSize: 21632, SharedKeySize: 32
NID: 0x20805, PubKeySize: 21520, PrivKeySize: 43088, CipherTextSize: 21632, SharedKeySize: 32
NID: 0x20900, PubKeySize: 330, PrivKeySize: 374, CipherTextSize: 346, SharedKeySize: 16
NID: 0x20901, PubKeySize: 197, PrivKeySize: 350, CipherTextSize: 236, SharedKeySize: 16
NID: 0x20902, PubKeySize: 378, PrivKeySize: 434, CipherTextSize: 402, SharedKeySize: 24
NID: 0x20903, PubKeySize: 225, PrivKeySize: 407, CipherTextSize: 280, SharedKeySize: 24
NID: 0x20904, PubKeySize: 462, PrivKeySize: 524, CipherTextSize: 486, SharedKeySize: 24
NID: 0x20905, PubKeySize: 274, PrivKeySize: 491, CipherTextSize: 336, SharedKeySize: 24
NID: 0x20906, PubKeySize: 564, PrivKeySize: 644, CipherTextSize: 596, SharedKeySize: 32
NID: 0x20907, PubKeySize: 335, PrivKeySize: 602, CipherTextSize: 410, SharedKeySize: 32
NID: 0x20908, PubKeySize: 330, PrivKeySize: 28, CipherTextSize: 330, SharedKeySize: 110
NID: 0x20909, PubKeySize: 197, PrivKeySize: 28, CipherTextSize: 197, SharedKeySize: 110
NID: 0x2090a, PubKeySize: 378, PrivKeySize: 32, CipherTextSize: 378, SharedKeySize: 126
NID: 0x2090b, PubKeySize: 225, PrivKeySize: 32, CipherTextSize: 225, SharedKeySize: 126
NID: 0x2090c, PubKeySize: 462, PrivKeySize: 39, CipherTextSize: 462, SharedKeySize: 154
NID: 0x2090d, PubKeySize: 274, PrivKeySize: 39, CipherTextSize: 274, SharedKeySize: 154
NID: 0x2090e, PubKeySize: 564, PrivKeySize: 48, CipherTextSize: 564, SharedKeySize: 188
NID: 0x2090f, PubKeySize: 335, PrivKeySize: 48, CipherTextSize: 335, SharedKeySize: 188

*/

UINT32   mPqcKemNid[] = {
// BIKE
  // PQC_CRYPTO_KEM_NID_BIKE1_L1_CPA,
  // PQC_CRYPTO_KEM_NID_BIKE1_L3_CPA,
  // PQC_CRYPTO_KEM_NID_BIKE1_L1_FO,
  // PQC_CRYPTO_KEM_NID_BIKE1_L3_FO,
/* stack overflow
// CLASSIC_MCELIECE
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_348864F,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_460896F,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6688128F,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_6960119F,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128,
  PQC_CRYPTO_KEM_NID_CLASSIC_MCELIECE_8192128F,
*/
// HQC
  PQC_CRYPTO_KEM_NID_HQC_128,
  PQC_CRYPTO_KEM_NID_HQC_192,
  PQC_CRYPTO_KEM_NID_HQC_256,
// KYBER
  PQC_CRYPTO_KEM_NID_KYBER_512,
  PQC_CRYPTO_KEM_NID_KYBER_768,
  PQC_CRYPTO_KEM_NID_KYBER_1024,
  PQC_CRYPTO_KEM_NID_KYBER_512_90S,
  PQC_CRYPTO_KEM_NID_KYBER_768_90S,
  PQC_CRYPTO_KEM_NID_KYBER_1024_90S,
// NTRU
  PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_509,
  PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_677,
  PQC_CRYPTO_KEM_NID_NTRU_HPS_2048_821,
  PQC_CRYPTO_KEM_NID_NTRU_HRSS_701,
// NTRUPRIME
  PQC_CRYPTO_KEM_NID_NTRULPR653,
  PQC_CRYPTO_KEM_NID_NTRULPR761,
  PQC_CRYPTO_KEM_NID_NTRULPR857,
  PQC_CRYPTO_KEM_NID_SNTRUP653,
  PQC_CRYPTO_KEM_NID_SNTRUP761,
  PQC_CRYPTO_KEM_NID_SNTRUP857,
// SABER
  PQC_CRYPTO_KEM_NID_LIGHTSABER_KEM,
  PQC_CRYPTO_KEM_NID_SABER_KEM,
  PQC_CRYPTO_KEM_NID_FIRESABER_KEM,
// FRODOKEM
  PQC_CRYPTO_KEM_NID_FRODOKEM_640_AES,
  PQC_CRYPTO_KEM_NID_FRODOKEM_640_SHAKE,
  PQC_CRYPTO_KEM_NID_FRODOKEM_976_AES,
  PQC_CRYPTO_KEM_NID_FRODOKEM_976_SHAKE,
  PQC_CRYPTO_KEM_NID_FRODOKEM_1344_AES,
  PQC_CRYPTO_KEM_NID_FRODOKEM_1344_SHAKE,
// SIKE
  PQC_CRYPTO_KEM_NID_SIDH_P434,
  PQC_CRYPTO_KEM_NID_SIDH_P434_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIDH_P503,
  PQC_CRYPTO_KEM_NID_SIDH_P503_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIDH_P610,
  PQC_CRYPTO_KEM_NID_SIDH_P610_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIDH_P751,
  PQC_CRYPTO_KEM_NID_SIDH_P751_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIKE_P434,
  PQC_CRYPTO_KEM_NID_SIKE_P434_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIKE_P503,
  PQC_CRYPTO_KEM_NID_SIKE_P503_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIKE_P610,
  PQC_CRYPTO_KEM_NID_SIKE_P610_COMPRESSED,
  PQC_CRYPTO_KEM_NID_SIKE_P751,
  PQC_CRYPTO_KEM_NID_SIKE_P751_COMPRESSED,
};

UINT8    SharedKey1[200];
UINT8    SharedKey2[200];
UINT8    CipherText2[22000];
UINT8    PubKey1[1400000];
UINT8    PubKey2[1400000];

/**
  Validate UEFI-OQS KEM Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidatePqcCryptKem (
  VOID
  )
{
  UINTN    Index;
  UINTN    Nid;
  VOID     *Context1;
  VOID     *Context2;
  BOOLEAN  Result;
  UINTN    PubKey1Size;
  UINTN    CipherText2Size;
  UINTN    SharedKey1Size;
  UINTN    SharedKey2Size;

  Print ("\nUEFI-OQS KEM Testing:\n");

  for (Index = 0; Index < ARRAY_SIZE(mPqcKemNid); Index++) {
    Nid = mPqcKemNid[Index];
    
    PrintData (
      "NID: 0x%x, ",
      Nid
      );
    PrintData (
      "PubKeySize: %d, ",
      PqcGetOqsKemPubKeySize(Nid)
      );
    PrintData (
      "PrivKeySize: %d, ",
      PqcGetOqsKemPrivKeySize(Nid)
      );
    PrintData (
      "CipherTextSize: %d, ",
      PqcGetOqsKemCipherTextSize(Nid)
      );
    PrintData (
      "SharedKeySize: %d\n",
      PqcGetOqsKemSharedKeySize(Nid)
      );

    // Alice 1
    Print ("New1 ... ");
    Context1 = PqcKemNewByNid (Nid);
    if (Context1 == NULL) {
      Print ("[FAIL]\n");
      continue;
    }
    Print ("GenKey1 ... ");
    Result = PqcKemGenerateKey (Context1);
    if (!Result) {
      Print ("[FAIL]\n");
      PqcKemFree (Context1);
      continue;
    }
    Print ("GetPub1 ... ");
    PubKey1Size = sizeof(PubKey1);
    Result = PqcKemGetPublicKey (Context1, PubKey1, &PubKey1Size);
    if (!Result) {
      Print ("[FAIL]\n");
      PqcKemFree (Context1);
      continue;
    }

    // Bob 1
    Print ("New2 ... ");
    Context2 = PqcKemNewByNid (Nid);
    if (Context2 == NULL) {
      Print ("[FAIL]\n");
      PqcKemFree (Context1);
      continue;
    }
    Print ("PqcKemEncap2 ... ");
    SharedKey2Size = sizeof(SharedKey2);
    CipherText2Size = sizeof(CipherText2);
    Result = PqcKemEncap (Context2, PubKey1, PubKey1Size, SharedKey2, &SharedKey2Size, CipherText2, &CipherText2Size);
    if (!Result) {
      Print ("[FAIL]\n");
      PqcKemFree (Context1);
      PqcKemFree (Context2);
      continue;
    }

    // Alice 2
    Print ("PqcKemDecap1 ... ");
    SharedKey1Size = sizeof(SharedKey1);
    Result = PqcKemDecap (Context1, SharedKey1, &SharedKey1Size, CipherText2, CipherText2Size);
    if (!Result) {
      Print ("[FAIL]\n");
      PqcKemFree (Context1);
      PqcKemFree (Context2);
      continue;
    }

    // Verify both
    Print ("Verify Size ... ");
    if (SharedKey1Size != SharedKey2Size) {
      Print ("[FAIL]\n");
      PqcKemFree (Context1);
      PqcKemFree (Context2);
      continue;
    }
    Print ("Verify Data ... ");
    if (CompareMem (SharedKey1, SharedKey2, SharedKey2Size) != 0) {
      Print ("[FAIL]\n");
      PqcKemFree (Context1);
      PqcKemFree (Context2);
      continue;
    }

    Print ("Free1 ... ");
    PqcKemFree (Context1);
    Print ("Free2 ... ");
    PqcKemFree (Context2);
    Print ("[PASS]\n");
  }

  return EFI_SUCCESS;
}