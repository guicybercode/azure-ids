#pragma once

#include <string>
#include <vector>

namespace AzureIDS {

class CryptoUtils {
public:
    static std::string hmac_sha256(const std::string& data, const std::string& key);
    static std::string sha256(const std::string& data);
    static std::string base64_encode(const std::string& data);
    static std::string base64_decode(const std::string& data);
    
    static std::string encrypt_aes(const std::string& data, const std::string& key);
    static std::string decrypt_aes(const std::string& encrypted_data, const std::string& key);
    
    static std::string generate_random_key(size_t length = 32);
    static std::string hash_password(const std::string& password, const std::string& salt);
    static bool verify_password(const std::string& password, const std::string& hash, const std::string& salt);

private:
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
};

}

