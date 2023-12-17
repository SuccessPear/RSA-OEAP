#include <iostream>
#include "KeyManagement.cpp"
#include "AES-GCM.cpp"
#include "ECDSA.cpp"
#include "HMAC-SHA256.cpp"
#include "RSA-OAEP.cpp"

int main() {
    // Initialize OpenSSL library
    OpenSSL_add_all_algorithms();

    // Generate RSA key pair
    RSA* privateKey = generateRSAKeyPair();
    RSA* publicKey = RSA_new();
    RSA_set0_key(publicKey, BN_dup(RSA_get0_n(privateKey)), BN_dup(RSA_get0_e(privateKey)), nullptr);

    // Generate AES key
    int aesKeySize = 32;  // 256 bits
    std::vector<unsigned char> aesKey = generateAESKey(aesKeySize);

    // Encrypt a message with AES-GCM
    std::string originalMessage = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'S', 'e', 'c', 'u', 'r', 'e', ' ', 'S', 'y', 's', 't', 'e', 'm', '!' };
    std::vector<unsigned char> aesCiphertext = aesGcmEncrypt(originalMessage, aesKey);

    // Encrypt the AES key with RSA-OAEP
    std::string strAESKey(aesKey.begin(), aesKey.end());
    std::vector<unsigned char> rsaEncryptedAesKey = rsaOaepEncrypt(strAESKey, publicKey);

    // Calculate HMAC-SHA256 for message authentication
    std::vector<unsigned char> hmacResult = calculateHmacSha256(originalMessage, aesKey);

    // Print the results
    std::cout << "Original Message: ";
    for (const auto& byte : originalMessage) {
        std::cout << byte;
    }
    std::cout << std::endl;

    std::cout << "AES-GCM Ciphertext: ";  // Print aesCiphertext
    for (const auto& byte : aesCiphertext) {
        printf("%02x", byte);
    }
    std::cout << std::endl;

    std::cout << "RSA-OAEP Encrypted AES Key: ";  // Print rsaEncryptedAesKey
    for (const auto& byte : rsaEncryptedAesKey) {
        printf("%02x", byte);
    }
    std::cout << std::endl;

    std::cout << "HMAC-SHA256: ";  // Print hmacResult
    for (const auto& byte : hmacResult) {
        printf("%02x", byte);
    }
    std::cout << std::endl;

    // Clean up resources
    RSA_free(privateKey);
    RSA_free(publicKey);

    // Clean up OpenSSL
    EVP_cleanup();

    return 0;
}