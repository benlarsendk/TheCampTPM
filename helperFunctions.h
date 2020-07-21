//
// Created by benlar on 21-07-2020.
//

#ifndef THECAMP_NETWORKMANAGER_HELPERFUNCTIONS_H
#define THECAMP_NETWORKMANAGER_HELPERFUNCTIONS_H

#include "openssl/sha.h"
#include "tss_includes.h"
#include "defines.h"

// Calculates the policydigest to use for the key when making exercise two
// The digests uses are the EXPECTED (trusted) file hashes.
TPM2B_DIGEST calculatePolicyDigestForFiles(TPML_PCR_SELECTION* PCRSelection){

    // Final digest to return
    TPM2B_DIGEST policyDigest;

    // We start by predicting the PCR Values (00 || avHash || dbHash)
    unsigned char nullHash[SHA256_DIGEST_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    unsigned char avHash[SHA256_DIGEST_SIZE] = {0xf5,0xfd,0x72,0x61,0xf4,0x62,0x6f,0x4c,0xc2,0x9f,0x4b,0xba,0x55,0xe8,0x6e,0x1e,0xa7,0x93,0x18,0x97,0xf6,0xdc,0xfa,0x51,0xa9,0x5a,0x29,0x64,0x87,0x4c,0xda,0x74};
    unsigned char dbHash[SHA256_DIGEST_SIZE] = {0x45,0x4f,0x29,0x70,0x00,0xc7,0xb6,0x2b,0xc4,0xd5,0x83,0x54,0x57,0xad,0x3c,0x67,0x84,0x2b,0x3d,0x34,0xc6,0x70,0x6d,0x66,0xea,0x6d,0x69,0xac,0x54,0x0f,0x99,0xd5};

    // "Extend" the two hashes
    unsigned char ExpectedPCR[SHA256_DIGEST_SIZE];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, nullHash, SHA256_DIGEST_SIZE);
    SHA256_Update(&sha256, avHash, SHA256_DIGEST_SIZE);
    SHA256_Final(ExpectedPCR, &sha256);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, ExpectedPCR, SHA256_DIGEST_SIZE);
    SHA256_Update(&sha256, dbHash, SHA256_DIGEST_SIZE);
    SHA256_Final(ExpectedPCR, &sha256);


    // Calculate PCR Accumulation (H(Pcr))
    unsigned char PCRRead[SHA256_DIGEST_SIZE];
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, ExpectedPCR, SHA256_DIGEST_SIZE);
    SHA256_Final(PCRRead, &sha256);

    unsigned char cc[4] = { 0x00, 0x00, 0x01, 0x7f }; // Command Code of PolicyPCR

    // Marshal the PCR Selection
    BYTE pcrs[sizeof(TPML_PCR_SELECTION)];
    BYTE* buffer;
    buffer = pcrs;
    UINT16 written = 0;
    TSS_TPML_PCR_SELECTION_Marshal(PCRSelection, &written, &buffer, NULL);

    // We then calculate the sessionDigest that  will be if the PCRs are correct in the TPM
    // S_d = H(S_d || CC || PCRSelection || PCR Content)
    SHA256_Init(&sha256);

    SHA256_Update(&sha256, nullHash, SHA256_DIGEST_SIZE); // Add "original"
    SHA256_Update(&sha256, cc, CC_SIZE); // Add Command Code
    SHA256_Update(&sha256, pcrs, written); // Add marshalled selection
    SHA256_Update(&sha256, PCRRead, SHA256_DIGEST_SIZE); // Add digest

    SHA256_Final(policyDigest.b.buffer, &sha256);
    policyDigest.b.size = SHA256_DIGEST_SIZE;

    // Return policy digest
    return policyDigest;
}

//
// Created by benlar on 21-07-2020.
//

#ifndef THECAMP_NETWORKMANAGER_FILEHASHING_H
#define THECAMP_NETWORKMANAGER_FILEHASHING_H

#include <cstdio>
#include <cstdlib>
#include <openssl/sha.h>


// (Don't use this function, it's a helper for hasHfile)
void readBinary(unsigned char** data, size_t* len, const char* location)
{
    *data = nullptr;
    *len = 0;

    // Open in binary mode
    FILE* f = fopen(location, "rb");
    if (f == nullptr) {
        printf("[-] Not able to find file %s\n", location);
        return;
    }

    // Find filesize
    fseek(f, 0, SEEK_END);
    *len = ftell(f);

    // Go back to beginning
    fseek(f, 0L, SEEK_SET);

    // Allocate memory
    *data = (unsigned char*)malloc(*len);

    // Read binary data
    fread(*data, 1, *len, f);

    // Close
    fclose(f);
}
#endif //THECAMP_NETWORKMANAGER_FILEHASHING_H

// Use this function to hash a file
void hashFile(char* filelocation, unsigned char* dataDigest){

    size_t length;
    unsigned char* binaryData = nullptr;

    readBinary(&binaryData, &length, filelocation);

    // Hash it
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, binaryData, length);
    SHA256_Final(dataDigest, &sha256);

    // Free datapointer
    free(binaryData);

}

#endif //THECAMP_NETWORKMANAGER_HELPERFUNCTIONS_H
