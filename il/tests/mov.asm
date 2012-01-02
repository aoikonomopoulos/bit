# Test cases for the mov instruction
BITS 32

mov eax,ebx
mov dword [eax], ebx
mov dword [eax + 0x100], ebx
mov eax, [ebx]
mov dword [eax + ebx*2], ecx
