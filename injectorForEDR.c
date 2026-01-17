#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <locale.h>
#include <tlhelp32.h>
#include <sddl.h>

int main() {
    char dllPath[] = "C:\\Users\\Admin\\source\\repos\\EDR\\x64\\Debug\\EDR.dll";
    DWORD PID;
    printf("=== edr found started / one moment ===\n");

    printf("enter pid process: ");
    scanf_s("%d", &PID);


    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hProcess == NULL) {
        printf("error: code: %lu\n", GetLastError());
        return 1;
    }

    LPVOID pAmyat = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pAmyat == NULL) {
        printf("error.\n");
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, pAmyat, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
        printf("Error.\n");
        VirtualFreeEx(hProcess, pAmyat, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pAmyat, 0, NULL);
    if (hThread == NULL) {
        printf("Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pAmyat, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("injected sucessfuly %lu\n");
    printf("monitoring started\n");
    while (1) {
        Sleep(1000); 
    }

    CloseHandle(hThread);
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pAmyat, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
