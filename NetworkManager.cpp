#include "NetworkManager.h"
#include "defines.h"
#include <cryptoutils.h>

// Returns a random nounce (SHA256 size, so no need for hashing)
unsigned char* NetworkManager::requestNonce() {
    printf("[*] NetworkManager generating nonce\n");
    RAND_bytes(this->last_nonce, SHA256_DIGEST_SIZE);
    return last_nonce;
}
void NetworkManager::verifySignature(TPMT_SIGNATURE &signature) {

    if(this->pk == nullptr){
        printf("[-] Key not provided, not not verifying\n");
        return;
    }
    // Verifies signature with previously provided key
    if(verifyEcSignatureFromEvpPubKey(this->last_nonce, SHA256_DIGEST_SIZE, &signature, this->pk) == SUCCESS)
        printf("[+] Signature verified\n");
    else{
        printf("[-] Could not verify signature\n");
    }

}
void NetworkManager::setPlatformPublicKey(TPM2B_PUBLIC &platformPublicKey) {

    printf("[*] Networking manager received public key\n");
    // Here you could verify the AuthPolicy and other verifications.
    // The actual public key is a simple ECC Point
    // The following convertion sets the local public key
    convertEcPublicToEvpPubKey(&this->pk, &platformPublicKey.publicArea.unique.ecc);
}
