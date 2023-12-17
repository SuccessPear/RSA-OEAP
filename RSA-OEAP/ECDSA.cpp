#include <iostream>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <vector>

// Function to sign a message using ECDSA
std::vector<unsigned char> signECDSAMessage(const std::string& message, EC_KEY* privateKey) {
    std::vector<unsigned char> signature;

    if (!privateKey) {
        std::cerr << "Invalid private key." << std::endl;
        return signature;
    }

    const unsigned char* msgData = reinterpret_cast<const unsigned char*>(message.c_str());
    size_t msgLen = message.length();

    ECDSA_SIG* ecdsaSignature = ECDSA_do_sign(msgData, static_cast<int>(msgLen), privateKey);
    if (!ecdsaSignature) {
        std::cerr << "Error signing message." << std::endl;
        return signature;
    }

    // Convert the signature components to DER format
    unsigned char* derSignature = nullptr;
    int derLength = i2d_ECDSA_SIG(ecdsaSignature, &derSignature);
    if (derLength > 0) {
        signature.assign(derSignature, derSignature + derLength);
        OPENSSL_free(derSignature);
    }
    else {
        std::cerr << "Error converting signature to DER format." << std::endl;
    }

    ECDSA_SIG_free(ecdsaSignature);
    return signature;
}

// Function to verify an ECDSA signature
bool verifyECDSASignature(const std::string& message, const std::vector<unsigned char>& signature, EC_KEY* publicKey) {
    if (!publicKey) {
        std::cerr << "Invalid public key." << std::endl;
        return false;
    }

    const unsigned char* msgData = reinterpret_cast<const unsigned char*>(message.c_str());
    size_t msgLen = message.length();

    // Parse DER-encoded signature
    const unsigned char* derSignature = signature.data();
    ECDSA_SIG* ecdsaSignature = d2i_ECDSA_SIG(nullptr, &derSignature, static_cast<long>(signature.size()));
    if (!ecdsaSignature) {
        std::cerr << "Error parsing DER-encoded signature." << std::endl;
        return false;
    }

    // Verify the signature
    int result = ECDSA_do_verify(msgData, static_cast<int>(msgLen), ecdsaSignature, publicKey);
    ECDSA_SIG_free(ecdsaSignature);

    return result == 1;
}