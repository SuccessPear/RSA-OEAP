#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>

// Function to generate a random key for AES-GCM
std::vector<unsigned char> generateAESKey(int keySize) {
    std::vector<unsigned char> key(keySize);
    if (RAND_bytes(key.data(), keySize) != 1) {
        std::cerr << "Error generating random key." << std::endl;
        return {};
    }
    return key;
}

// Function to perform AES-GCM encryption
std::vector<unsigned char> aesGcmEncrypt(const std::string& plaintext, const std::vector<unsigned char>& key) {
    // Generate a random IV (Initialization Vector)
    std::vector<unsigned char> iv(EVP_CIPHER_iv_length(EVP_aes_256_gcm()));
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        std::cerr << "Error generating random IV." << std::endl;
        return {};
    }

    // Set up the encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
        std::cerr << "Error setting up encryption context." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Perform encryption
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        std::cerr << "Error performing encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Finalize encryption (including authentication tag)
    int finalLen;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &finalLen) != 1) {
        std::cerr << "Error finalizing encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(len + finalLen);
    return ciphertext;
}

// Function to perform AES-GCM decryption
std::string aesGcmDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key) {
    // Extract IV from the ciphertext
    std::vector<unsigned char> iv(EVP_CIPHER_iv_length(EVP_aes_256_gcm()));
    std::copy(ciphertext.begin(), ciphertext.begin() + iv.size(), iv.begin());

    // Set up the decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1) {
        std::cerr << "Error setting up decryption context." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Perform decryption
    std::vector<unsigned char> plaintext(ciphertext.size() - EVP_CIPHER_iv_length(EVP_aes_256_gcm()));
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data() + iv.size(), plaintext.size()) != 1) {
        std::cerr << "Error performing decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Finalize decryption (including authentication tag verification)
    int finalLen;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &finalLen) != 1) {
        std::cerr << "Error finalizing decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(len + finalLen);
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
}