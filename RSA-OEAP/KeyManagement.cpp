#include <iostream>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

RSA* generateRSAKeyPair() {
    RSA* key = RSA_new();
    BIGNUM* e = BN_new();

    // Set the public exponent (65537 is commonly used)
    BN_set_word(e, RSA_F4);

    if (RSA_generate_key_ex(key, 2048, e, nullptr) != 1) {
        std::cerr << "Error generating RSA key pair." << std::endl;
        RSA_free(key);
        BN_free(e);
        return nullptr;
    }

    BN_free(e);
    return key;
}

EC_KEY* generateSecp256k1KeyPair() {
    // Create an EC_KEY structure
    EC_KEY* key = EC_KEY_new_by_curve_name(OBJ_sn2nid("secp256k1"));
    if (!key) {
        std::cerr << "Error creating EC_KEY structure." << std::endl;
        return nullptr;
    }

    // Generate the ECC key pair
    if (EC_KEY_generate_key(key) != 1) {
        std::cerr << "Error generating secp256k1 ECC key pair." << std::endl;
        EC_KEY_free(key);
        return nullptr;
    }

    return key;
}

EC_KEY* parseECKeyFromPEM(const char* pemKey) {
    BIO* bio = BIO_new_mem_buf(pemKey, -1);
    if (!bio) {
        std::cerr << "Error creating BIO." << std::endl;
        return nullptr;
    }

    EC_KEY* ecKey = PEM_read_bio_ECPrivateKey(bio, nullptr, nullptr, nullptr);
    if (!ecKey) {
        std::cerr << "Error parsing ECC private key from PEM." << std::endl;
    }

    BIO_free(bio);
    return ecKey;
}

RSA* parseRSAKeyFromPEM(const char* pemKey) {
    BIO* bio = BIO_new_mem_buf(pemKey, -1);
    if (!bio) {
        std::cerr << "Error creating BIO." << std::endl;
        return nullptr;
    }

    RSA* rsaKey = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    if (!rsaKey) {
        std::cerr << "Error parsing RSA private key from PEM." << std::endl;
    }

    BIO_free(bio);
    return rsaKey;
}