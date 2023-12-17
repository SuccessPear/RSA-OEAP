#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <vector>

// Function to perform RSA-OAEP encryption
std::vector<unsigned char> rsaOaepEncrypt(const std::string& plaintext, RSA* publicKey) {
    std::vector<unsigned char> ciphertext(RSA_size(publicKey));

    if (RSA_public_encrypt(plaintext.size(), reinterpret_cast<const unsigned char*>(plaintext.c_str()),
        ciphertext.data(), publicKey, RSA_PKCS1_OAEP_PADDING) == -1) {
        std::cerr << "Error performing RSA-OAEP encryption." << std::endl;
        return {};
    }

    return ciphertext;
}

// Function to perform RSA-OAEP decryption
std::string rsaOaepDecrypt(const std::vector<unsigned char>& ciphertext, RSA* privateKey) {
    std::vector<unsigned char> plaintext(RSA_size(privateKey));

    int plaintextSize = RSA_private_decrypt(ciphertext.size(), ciphertext.data(), plaintext.data(),
        privateKey, RSA_PKCS1_OAEP_PADDING);

    if (plaintextSize == -1) {
        std::cerr << "Error performing RSA-OAEP decryption." << std::endl;
        return {};
    }

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintextSize);
}