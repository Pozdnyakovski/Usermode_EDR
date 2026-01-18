Demonstation:
https://github.com/user-attachments/assets/611f6402-2361-43f3-84e9-0c571486e454


1) Hooks on suspicious functions are used to detect UAC bypass via fodhelper.exe.
2) Hardware breakpoints are used - specifically CPU registers (dr0–dr3/dr7) that store function addresses - to detect NtCreateThreadEx.
3) A IAT-hook on the VEH handler prevents malware from placing its own handler above mine to bypass HWBP detection.
4) Anti‑debugging technique implemented in 5 minutes using the PEB instead of directly calling IsDebuggerPresent.
5) <img width="647" height="175" alt="изображение" src="https://github.com/user-attachments/assets/c1bf7686-9313-4442-bf72-02ac08c266b6" />
6) Hooks on GetThreadContext/SetThreadContext prevent malware from reading the state of registers (dr0–dr3) to detect monitoring or attempting to clear them via SetThreadContext.
7) For testing, I wrote a dropper in FASM assembly myself; all checks were performed using it.
8) СaptureStackBackTrace is used to determine whether code is executed from the .text section or from the heap, which serves as clear evidence of payload injection into the process.
