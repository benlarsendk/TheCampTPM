#ifndef THECAMP_TPMMANAGER_H
#define THECAMP_TPMMANAGER_H

#include <ibmtss/tss.h>

class TpmManager {
public:
    void boot_tpm(TSS_CONTEXT *ctx);
    void pcrExtend(TSS_CONTEXT *ctx, unsigned char *binaryHash, uint8_t pcr);
    Load_Out load_key(TSS_CONTEXT *ctx, TPM_HANDLE parent, Create_Out &sealedKey); // Free functions WUHU :D

    // Maybe a way to start a session (StartAuthSession)?
    // Should also have a way to flush sessions and keys (FlushContext)
    // We definetly need someway to sign (TPM2_Sign)
    // Maybe a function for creating a primary key?
    // Uhh! And a function to create a key with a primary key as parent!
    // A function to execute a policyPCR would be nice!
private:
    void handle_TPM_error();
    int last_err;

};


#endif //THECAMP_TPMMANAGER_H
