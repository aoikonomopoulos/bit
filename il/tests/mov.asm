# Test cases for the mov instruction
BITS 32

mov eax,ebx
mov dword [eax], ebx
mov eax, [ebx]
mov dword [eax + 0x100], ebx
mov eax, [ebx + 0x100]
mov dword [eax + ebx*2], ecx
mov eax, [ebx + ecx*2]
mov dword [eax + ebx*2 + 0x100], ecx
mov eax, [ebx + ecx*2 + 0x100]
