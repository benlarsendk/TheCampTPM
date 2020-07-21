

#include "TpmManager.h"
#include "NetworkManager.h"

int main() {
    TSS_SetProperty(nullptr, TPM_TRACE_LEVEL, "1"); // 1 is normal 2 is debug


    TpmManager tpm; // Create tpm manager
    NetworkManager networkManager; // network manager

    // Creates a TSS Context. Use this context in all functions you want to call. When you exit the program, delete it.
    TSS_CONTEXT* ctx;
    TSS_Create(&ctx);

    // Boots your software TPM
    tpm.boot_tpm(ctx);

    /* Your brilliant code here
     *
     * Start with the first exercise.
     * A rough way to start: Create primary key (no password, no policy), create key with primary key
     * as parent (no password, no policy), send the key to the networkmanager, request a nonce,
     * load the key (that function you already have!), execute a sign and send the signature to network manager
     * for verification. Good luck :)
     *
     *
     *
     * If you make it to exercise two, run this code immediatly after tpm_boot.
     * It is here to emmulate the trusted measurement done after boot.
     *   // Obtain file hashes (Assumed done on boot)
          unsigned char antivirusHash[SHA256_DIGEST_SIZE];
          unsigned char dbHash[SHA256_DIGEST_SIZE];

          hashFile("../Antivirus.txt",antivirusHash);
          hashFile("../database.txt",dbHash);

          // Execute PCR Extend for PCR 16 for both hashes
          tpm.pcrExtend(ctx,antivirusHash,15);
          tpm.pcrExtend(ctx,dbHash,15);
     * */


    // Delete context
    TSS_Delete(ctx);

}
