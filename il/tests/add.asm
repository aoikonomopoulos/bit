# Test cases for the ADD instruction
BITS 32

add eax,ebx
add dword [eax], ebx
add dword [eax + 0x100], ebx
add eax, [ebx]
add dword [eax + ebx*2], ecx

add ax,bx
