//
// Created by benlar on 21-07-2020.
//

#ifndef THECAMP_NETWORKMANAGER_H
#define THECAMP_NETWORKMANAGER_H

#include <openssl/ossl_typ.h>
#include "ibmtss/TPM_Types.h"
class NetworkManager {

public:
    void setPlatformPublicKey(TPM2B_PUBLIC& platformPublicKey);
    unsigned char* requestNonce();
    void verifySignature(TPMT_SIGNATURE& signature);

private:
    EVP_PKEY* pk = nullptr; // OpenSSL version of key
    unsigned char last_nonce[SHA256_DIGEST_SIZE];
};


#endif //THECAMPSTUFF_NETWORKMANAGER_H
