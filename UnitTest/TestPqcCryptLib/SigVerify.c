/** @file
  Application for OQS-SIG Primitives Validation.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PqcCryptest.h"

/*
UEFI-OQS SIG Testing:
NID: 0x10100, PubKeySize: 1312, PrivKeySize: 2528, SignatureSize: 2420
NID: 0x10101, PubKeySize: 1952, PrivKeySize: 4000, SignatureSize: 3293
NID: 0x10102, PubKeySize: 2592, PrivKeySize: 4864, SignatureSize: 4595
NID: 0x10103, PubKeySize: 1312, PrivKeySize: 2528, SignatureSize: 2420
NID: 0x10104, PubKeySize: 1952, PrivKeySize: 4000, SignatureSize: 3293
NID: 0x10105, PubKeySize: 2592, PrivKeySize: 4864, SignatureSize: 4595
NID: 0x10200, PubKeySize: 897, PrivKeySize: 1281, SignatureSize: 690
NID: 0x10201, PubKeySize: 1793, PrivKeySize: 2305, SignatureSize: 1330
NID: 0x10300, PubKeySize: 161600, PrivKeySize: 103648, SignatureSize: 66
NID: 0x10301, PubKeySize: 60192, PrivKeySize: 103648, SignatureSize: 66
NID: 0x10302, PubKeySize: 60192, PrivKeySize: 64, SignatureSize: 66
NID: 0x10400, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x10401, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x10402, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x10403, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x10404, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x10405, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x10406, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x10407, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x10408, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x10409, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x1040a, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x1040b, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x1040c, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x1040d, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x1040e, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x1040f, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x10410, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x10411, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x10412, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x10413, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x10414, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x10415, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x10416, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x10417, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x10418, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x10419, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 16976
NID: 0x1041a, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x1041b, PubKeySize: 32, PrivKeySize: 64, SignatureSize: 8080
NID: 0x1041c, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x1041d, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 35664
NID: 0x1041e, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x1041f, PubKeySize: 48, PrivKeySize: 96, SignatureSize: 17064
NID: 0x10420, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x10421, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 49216
NID: 0x10422, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x10423, PubKeySize: 64, PrivKeySize: 128, SignatureSize: 29792
NID: 0x10500, PubKeySize: 33, PrivKeySize: 49, SignatureSize: 34036
NID: 0x10501, PubKeySize: 33, PrivKeySize: 49, SignatureSize: 53965
NID: 0x10502, PubKeySize: 35, PrivKeySize: 52, SignatureSize: 32065
NID: 0x10503, PubKeySize: 49, PrivKeySize: 73, SignatureSize: 76776
NID: 0x10504, PubKeySize: 49, PrivKeySize: 73, SignatureSize: 121849
NID: 0x10505, PubKeySize: 49, PrivKeySize: 73, SignatureSize: 71183
NID: 0x10506, PubKeySize: 65, PrivKeySize: 97, SignatureSize: 132860
NID: 0x10507, PubKeySize: 65, PrivKeySize: 97, SignatureSize: 209510
NID: 0x10508, PubKeySize: 65, PrivKeySize: 97, SignatureSize: 126290
NID: 0x10509, PubKeySize: 35, PrivKeySize: 52, SignatureSize: 14612
NID: 0x1050a, PubKeySize: 49, PrivKeySize: 73, SignatureSize: 35028
NID: 0x1050b, PubKeySize: 65, PrivKeySize: 97, SignatureSize: 61028
*/

UINT32   mPqcSigNid[] = {
// DILITHIUM
  PQC_CRYPTO_SIG_NID_DILITHIUM_2,
  PQC_CRYPTO_SIG_NID_DILITHIUM_3,
  PQC_CRYPTO_SIG_NID_DILITHIUM_5,
  PQC_CRYPTO_SIG_NID_DILITHIUM_2_AES,
  PQC_CRYPTO_SIG_NID_DILITHIUM_3_AES,
  PQC_CRYPTO_SIG_NID_DILITHIUM_5_AES,
// FALCON
  PQC_CRYPTO_SIG_NID_FALCON_512,
  PQC_CRYPTO_SIG_NID_FALCON_1024,
// RAINBOW
  PQC_CRYPTO_SIG_NID_RAINBOW_I_CLASSIC,
  PQC_CRYPTO_SIG_NID_RAINBOW_I_CIRCUMZENITHAL,
  PQC_CRYPTO_SIG_NID_RAINBOW_I_COMPRESSED,
  //PQC_CRYPTO_SIG_NID_RAINBOW_III_CLASSIC,
  //PQC_CRYPTO_SIG_NID_RAINBOW_III_CIRCUMZENITHAL,
  //PQC_CRYPTO_SIG_NID_RAINBOW_III_COMPRESSED,
  //PQC_CRYPTO_SIG_NID_RAINBOW_V_CLASSIC,
  //PQC_CRYPTO_SIG_NID_RAINBOW_V_CIRCUMZENITHAL,
  //PQC_CRYPTO_SIG_NID_RAINBOW_V_COMPRESSED,
// SPHINCS
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_128S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_192S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_HARAKA_256S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_128S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_192S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHA256_256S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_128S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_192S_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256F_SIMPLE,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_ROBUST,
  PQC_CRYPTO_SIG_NID_SPHINCS_SHAKE256_256S_SIMPLE,
// PICNIC
  PQC_CRYPTO_SIG_NID_PICNIC_L1_FS,
  PQC_CRYPTO_SIG_NID_PICNIC_L1_UR,
  PQC_CRYPTO_SIG_NID_PICNIC_L1_FULL,
  PQC_CRYPTO_SIG_NID_PICNIC_L3_FS,
  PQC_CRYPTO_SIG_NID_PICNIC_L3_UR,
  PQC_CRYPTO_SIG_NID_PICNIC_L3_FULL,
  PQC_CRYPTO_SIG_NID_PICNIC_L5_FS,
  PQC_CRYPTO_SIG_NID_PICNIC_L5_UR,
  PQC_CRYPTO_SIG_NID_PICNIC_L5_FULL,
  PQC_CRYPTO_SIG_NID_PICNIC3_L1,
  PQC_CRYPTO_SIG_NID_PICNIC3_L3,
  PQC_CRYPTO_SIG_NID_PICNIC3_L5,
};

UINT8    Signature[210000];

/**
  Validate UEFI-OQS SIG Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidatePqcCryptSig (
  VOID
  )
{
  UINTN    Index;
  UINTN    Nid;
  VOID     *Context;
  BOOLEAN  Result;
  UINT8    Data[8] = "1234567";
  UINTN    DataSize = sizeof(Data);
  UINTN    SigSize;

  Print ("\nUEFI-OQS SIG Testing:\n");

  for (Index = 0; Index < ARRAY_SIZE(mPqcSigNid); Index++) {
    Nid = mPqcSigNid[Index];
    
    PrintData (
      "NID: 0x%x, ",
      Nid
      );
    PrintData (
      "PubKeySize: %d, ",
      PqcGetOqsSigPubKeySize(Nid)
      );
    PrintData (
      "PrivKeySize: %d, ",
      PqcGetOqsSigPrivKeySize(Nid)
      );
    PrintData (
      "SignatureSize: %d\n",
      PqcGetOqsSigSignatureSize(Nid)
      );

    Print ("New ... ");
    Context = PqcSigNewByNid (Nid);
    if (Context == NULL) {
      Print ("[FAIL]\n");
      continue;
    }
    Print ("GenKey ... ");
    Result = PqcSigGenerateKey (Context);
    if (!Result) {
      Print ("[FAIL]\n");
      PqcSigFree (Context);
      continue;
    }

    Print ("Sign ... ");
    SigSize = sizeof(Signature);
    Result = PqcSigSign (Context, Data, DataSize, Signature, &SigSize);
    if (!Result) {
      Print ("[FAIL]\n");
      PqcSigFree (Context);
      continue;
    }

    Print ("Verify ... ");
    Result = PqcSigVerify (Context, Data, DataSize, Signature, SigSize);
    if (!Result) {
      Print ("[FAIL]\n");
      PqcSigFree (Context);
      continue;
    }

    Print ("Free ... ");
    PqcSigFree (Context);
    Print ("[PASS]\n");
  }

  return EFI_SUCCESS;
}