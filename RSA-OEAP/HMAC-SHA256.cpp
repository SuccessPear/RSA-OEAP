#include <iostream>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <vector>

// Function to calculate HMAC-SHA256
std::vector<unsigned char> calculateHmacSha256(const std::string& message, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> result(SHA256_DIGEST_LENGTH);

    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.data(), static_cast<int>(key.size()), EVP_sha256(), nullptr);
    HMAC_Update(ctx, reinterpret_cast<const unsigned char*>(message.c_str()), message.size());
    HMAC_Final(ctx, result.data(), nullptr);
    HMAC_CTX_free(ctx);

    return result;
}