/*author: Pozdnyakovski*/

#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <winternl.h>

//typedef int(WINAPI* PMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
//PMessageBoxA OriginalMessageBoxA = NULL;

typedef struct {
    int processId;          
    char type[32];          
    char description[256];  
} EDR_EVENT;

typedef NTSTATUS(NTAPI* PNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );
PNtAllocateVirtualMemory OriginalNtAllocateVirtualMemory = NULL;

typedef NTSTATUS(NTAPI* PNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,    // r9
    IN PVOID StartRoutine,     
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,       
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList OPTIONAL
    );
PNtCreateThreadEx OriginalNtCreateThreadEx = NULL;

PVOID addrNtAllocate = NULL;
PVOID addrNtCreateThread = NULL;
LONG WINAPI HardwareBreakpointHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    PVOID faultAddr = ExceptionInfo->ExceptionRecord->ExceptionAddress;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        void* returnAddress = NULL;
        if (CaptureStackBackTrace(2, 1, &returnAddress, NULL) > 0)
        {
            HMODULE hMod = NULL;
            if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)returnAddress, &hMod))
            {
                TerminateProcess(GetCurrentProcess(), 0xDEAD1);
            }
        }
        if (faultAddr == addrNtCreateThread)
        {
            HANDLE hTargetProc = (HANDLE)ctx->R9; 
            PVOID startRountine = *(PVOID*)(ctx->Rsp + 40);

            if (hTargetProc != (HANDLE)-1 && GetProcessId(hTargetProc) != GetCurrentProcessId())
            {
                MessageBoxA(0, "detect use NtCreateThreadEx", "EDR", MB_ICONERROR);
                TerminateProcess(GetCurrentProcess(), 0);
            }
        }
        ctx->EFlags |= (1 << 16);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
typedef PVOID(WINAPI* PAddVectoredExceptionHandler)(
    ULONG First,
    PVECTORED_EXCEPTION_HANDLER Handler
    );
PAddVectoredExceptionHandler OriginalAddVectoredExeceptionHandler = NULL;

typedef BOOL(WINAPI* PGetThreadContext)(
    HANDLE hThread,
    LPCONTEXT lpContext  
    );
PGetThreadContext OriginalGetThreadContext = NULL;

typedef BOOL(WINAPI* PSetThreadContext)(
    HANDLE hThread,
    const CONTEXT* lpContext  
   );
PSetThreadContext OriginalSetThreadContext = NULL;

typedef LSTATUS(WINAPI* PRegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
PRegCreateKeyExA OriginalRegCreateKeyExA = NULL;

typedef HINSTANCE(WINAPI* PShellExecuteA)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
PShellExecuteA OriginalPShellExecuteA = NULL;

typedef LSTATUS(WINAPI* PRegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
PRegSetValueExA OriginalRegSetValueExA = NULL;

void SetHardwareBreakpoint(PVOID address, int index)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        if (index == 0) ctx.Dr0 = (DWORD64)address;
        else if (index == 1) ctx.Dr1 = (DWORD64)address;
        else if (index == 2) ctx.Dr2 = (DWORD64)address;
        else if (index == 3) ctx.Dr3 = (DWORD64)address;

        ctx.Dr7 |= (1ULL << (index * 2));

        if (!SetThreadContext(hThread, &ctx));
    }
}

void anti()
{
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged)
    {
        Sleep(1400);
        TerminateProcess(GetCurrentProcess(), 0);
    }
}


// IPC tonel

//void SendAlert(const char* type, const char* msg)
//{
//    HANDLE hPipe;
//    EDR_EVENT event;
//    DWORD bytesWritten;
//
//    event.processId = GetCurrentProcessId();
//    strcpy_s(event.type, sizeof(event.type), type);
//    strcpy_s(event.description, sizeof(event.description), msg);
//
//    hPipe = CreateFileA("\\\\.\\pipe\\dutyfree", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
//
//    if (hPipe != INVALID_HANDLE_VALUE)
//    {
//        WriteFile(hPipe, &event, sizeof(EDR_EVENT), &bytesWritten, NULL);
//        CloseHandle(hPipe);
//    }
//}


NTSTATUS HookPNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSIZE, ULONG AllocationType, ULONG Protect)
{
    if (ProcessHandle != (HANDLE)-1 && ProcessHandle != GetCurrentProcess())
    {
        MessageBoxA(0, "Hooked NtAllocateVirtualMemory.", "EDR", MB_ICONERROR);
        TerminateProcess(GetCurrentProcess(), 0);
        return ERROR_ACCESS_DENIED;
    }
    if (Protect == PAGE_EXECUTE_READWRITE)
    {
        MessageBoxA(0, "Detect used R/W//X prefix", "EDR", MB_ICONERROR);
    }
    return OriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSIZE, AllocationType, Protect);
}

LSTATUS WINAPI HookRegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    if (hKey == HKEY_CURRENT_USER)
    {
        TerminateProcess(GetCurrentProcess(), 0);
    }
    return OriginalRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

HINSTANCE WINAPI HookShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd) {
    if (lpFile != NULL)
    {
        if (_stricmp(lpFile, "fodhelper.exe") == 0)
        {
            MessageBoxA(0, "Detect fodhelper(UAC-Bypass)", "EDR", MB_ICONERROR);
            return (HINSTANCE)ERROR_ACCESS_DENIED;
        }
    }
        return OriginalPShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

LSTATUS WINAPI HookRegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
    if (lpSubKey != NULL)
    {
        if (_stricmp(lpSubKey, "Software\\Classes\\ms-settings\\shell\\open\\command") == 0)
        {
            MessageBoxA(0, "attempt to reconfigure ms-command!", "EDR", 0);
            TerminateProcess(GetCurrentProcess(), 0);
            return ERROR_ACCESS_DENIED;
        }
    }
        return OriginalRegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}
BOOL WINAPI HookGetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    BOOL result = OriginalGetThreadContext(hThread, lpContext);
    
    if (result && lpContext != NULL)
    {
        if ((lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS)
        {
            lpContext->Dr0 = 0;
            lpContext->Dr1 = 0;
            lpContext->Dr2 = 0;
            lpContext->Dr3 = 0;
            lpContext->Dr7 = 0;
        }
    }
    return result;
}

BOOL WINAPI HookSetThreadContext(HANDLE hThread, const CONTEXT *lpContext)
{
    if (lpContext == NULL)
    {
        return OriginalSetThreadContext(hThread, lpContext);
    }

    if ((lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS)
    {
        if (lpContext->Dr0 == 0 && lpContext->Dr1 == 0 && lpContext->Dr2 == 0)
        {
            TerminateProcess(GetCurrentProcess(), 0);
        }
    }
    return OriginalSetThreadContext(hThread, lpContext);
}
PVOID WINAPI HookAddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
{
    if (First != 0)
    {
        TerminateProcess(GetCurrentProcess(), 0);
    }
    return OriginalAddVectoredExeceptionHandler(First, Handler);
}

void InstallIATHook() {
    OriginalNtAllocateVirtualMemory = (PNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    addrNtCreateThread = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    if (addrNtCreateThread)
    {
        AddVectoredExceptionHandler(1, HardwareBreakpointHandler);
        SetHardwareBreakpoint(addrNtCreateThread, 1);
    }
    HMODULE hBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hBase + dosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hBase + importDir.VirtualAddress);

    HMODULE hSelf = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        (LPCSTR)InstallIATHook,
        &hSelf))

    OriginalRegSetValueExA = (PRegSetValueExA)GetProcAddress(GetModuleHandleA("advapi32.dll"), "RegSetValueExA");
    OriginalRegCreateKeyExA = (PRegCreateKeyExA)GetProcAddress(GetModuleHandleA("advapi32.dll"), "RegCreateKeyExA");
    OriginalPShellExecuteA = (PShellExecuteA)GetProcAddress(GetModuleHandleA("shell32.dll"), "ShellExecuteA");
    OriginalSetThreadContext = (PSetThreadContext)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetThreadContext");
    OriginalGetThreadContext = (PGetThreadContext)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetThreadContext");
    OriginalAddVectoredExeceptionHandler = (PAddVectoredExceptionHandler)GetProcAddress(GetModuleHandleA("kernel32.dll"), "AddVectoredExceptionHandler");

    while (importDesc->Name) {
        char* dllName = (char*)((BYTE*)hBase + importDesc->Name);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hBase + importDesc->FirstThunk);

        if (_stricmp(dllName, "advapi32.dll") == 0) {
            while (thunk->u1.Function) {
                if ((PVOID)thunk->u1.Function == (PVOID)OriginalRegSetValueExA) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (DWORD_PTR)HookRegSetValueExA;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);
                }
                else if ((PVOID)thunk->u1.Function == (PVOID)OriginalRegCreateKeyExA) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (DWORD_PTR)HookRegCreateKeyExA;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);
                }
                thunk++;
            }
        }
        else if (_stricmp(dllName, "shell32.dll") == 0) {
            while (thunk->u1.Function) {
                if ((PVOID)thunk->u1.Function == (PVOID)OriginalPShellExecuteA) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (DWORD_PTR)HookShellExecuteA;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);
                }
                thunk++;
            }
        }
        else if (_stricmp(dllName, "ntdll.dll") == 0) {
            while (thunk->u1.Function) {
                if ((PVOID)thunk->u1.Function == (PVOID)OriginalNtAllocateVirtualMemory) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (DWORD_PTR)HookPNtAllocateVirtualMemory;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);
                }
                thunk++;
            }
        }
        else if (_stricmp(dllName, "kernel32.dll") == 0) {
            while (thunk->u1.Function) {
                if ((PVOID)thunk->u1.Function == (PVOID)OriginalSetThreadContext) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (DWORD_PTR)HookSetThreadContext;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);
                }

                else if ((PVOID)thunk->u1.Function == (PVOID)OriginalGetThreadContext) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (DWORD_PTR)HookGetThreadContext;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);
                }
                else if ((PVOID)thunk->u1.Function == (PVOID)OriginalAddVectoredExeceptionHandler) {
                    DWORD oldProtect;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);
                    thunk->u1.Function = (DWORD_PTR)HookAddVectoredExceptionHandler;
                    VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);
                }
                thunk++;
            }
        }
        importDesc++;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    setlocale(LC_ALL, "RU");
    if (reason == DLL_PROCESS_ATTACH) {
        anti();
        InstallIATHook();
    }
    return TRUE;
}
