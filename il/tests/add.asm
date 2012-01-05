# Test cases for the ADD instruction
BITS 32

add eax, 0x100
add eax,ebx
add dword [eax], 0x100 
add dword [eax], ebx
add eax, dword [ebx]
add dword [eax + 0x100], ebx
add eax, dword [ebx + 0x100] 
add dword [eax + ebx*2], ecx
add eax, dword [ebx + ecx*2]
add [0x100], eax
add eax, [0x100]
