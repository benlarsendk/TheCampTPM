//
// Created by s180222 on 04-02-2020.
//

#include <string>
#include "TpmManager.h"
#include "tss_includes.h"
#include "defines.h"
#include <cstring> // memcpy

#ifdef WIN32
#pragma comment(lib, "Ws2_32.lib") // htonl
#endif


/* Runs a powercycle on the (software) TPM */
void TpmManager::boot_tpm(TSS_CONTEXT *user_ctx) {
#ifndef HWTPM

#ifdef VERBOSE
    printf("[*] Running TPM Powercycle\n");
#endif

    TSS_CONTEXT* ctx = nullptr;
    last_err = TSS_Create(&ctx);

    last_err = TSS_TransmitPlatform(ctx, TPM_SIGNAL_POWER_OFF, "TPM2_PowerOffPlatform");
    if (last_err != SUCCESS) handle_TPM_error();
    last_err = TSS_TransmitPlatform(ctx, TPM_SIGNAL_POWER_ON, "TPM2_PowerOnPlatform");
    if (last_err != SUCCESS) handle_TPM_error();
    last_err = TSS_TransmitPlatform(ctx, TPM_SIGNAL_NV_ON, "TPM2_NvOnPlatform");
    if (last_err != SUCCESS) handle_TPM_error();

    TSS_Delete(ctx);

    Startup_In in;
    in.startupType = TPM_SU_CLEAR;
    last_err = TSS_Execute(user_ctx,
                           nullptr,
                           (COMMAND_PARAMETERS*)&in,
                           nullptr,
                           TPM_CC_Startup,
                           TPM_RH_NULL, NULL, 0);
#endif


}




void TpmManager::handle_TPM_error() {
    const char *msg;
    const char *submsg;
    const char *num;

    TSS_ResponseCode_toString(&msg, &submsg, &num, static_cast<TPM_RC>(last_err));
    printf("[-] An error occured: %s (%s %s)\n", msg, submsg, num);

}

// Extend a PCR register with a hash in the TPM
void TpmManager::pcrExtend(TSS_CONTEXT *ctx, unsigned char *binaryHash, uint8_t pcr)
{

#ifdef VERBOSE
    printf("[*] Executing PCR Extend\n");
#endif

    PCR_Extend_In 		in;

    in.digests.count = 1;
    in.digests.digests[0].hashAlg = TPM_ALG_SHA256;
    in.pcrHandle = pcr;
    memcpy((uint8_t*)&in.digests.digests[0].digest, binaryHash, SHA256_DIGEST_SIZE); // Can be optimized

    last_err = TSS_Execute(ctx,
                           nullptr,
                           (COMMAND_PARAMETERS*)&in,
                           nullptr,
                           TPM_CC_PCR_Extend,
                           TPM_RS_PW, NULL, 0,
                           TPM_RH_NULL, NULL, 0);
    if (last_err != SUCCESS) handle_TPM_error();
}


// Here is an example how to send a command to the TPM.
// Remember: Load key is only for normal keys - a primary key has to be created :)
Load_Out TpmManager::load_key(TSS_CONTEXT *ctx, TPM_HANDLE parent, Create_Out &sealedKey) {
#ifdef VERBOSE
    printf("[*] Loading key\n");
#endif

    // Input and output
    Load_In in;
    Load_Out out;

    // Session handles - the first is TPM_RS_PW since it *could* have a password for the parent
    // The last two sessions are unused in our context
    TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
    unsigned int sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    unsigned int sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes2 = 0;

    // We set the private and public data
    // Remember the private data is encrypted, and this load key command decrypts it with the parent
    in.inPrivate = sealedKey.outPrivate;
    in.inPublic = sealedKey.outPublic;

    // The parent of this key, e.g. the key that has to decrypt this key
    in.parentHandle = parent;

    // Execute the commmand
    last_err = TSS_Execute(ctx,
                           (RESPONSE_PARAMETERS *) &out,
                           (COMMAND_PARAMETERS *) &in,
                           nullptr,
                           TPM_CC_Load,
                           sessionHandle0, NULL, sessionAttributes0,
                           sessionHandle1, NULL, sessionAttributes1,
                           sessionHandle2, NULL, sessionAttributes2,
                           TPM_RH_NULL, NULL, 0);
    if (last_err != SUCCESS) handle_TPM_error();

    // Return the out strucutre.
    // This structure has a keyhandle (reference to the loaded key) and a hash of the public part (name).
    // Key handle is found in out.objecthandle.
    return out;
}





