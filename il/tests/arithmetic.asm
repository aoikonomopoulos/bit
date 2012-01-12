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

sub eax, 0x100
sub eax,ebx
sub dword [eax], 0x100 
sub dword [eax], ebx
sub eax, dword [ebx]
sub dword [eax + 0x100], ebx
sub eax, dword [ebx + 0x100] 
sub dword [eax + ebx*2], ecx
sub eax, dword [ebx + ecx*2]
sub [0x100], eax
sub eax, [0x100]

mul ebx
mul dword [ebx]
mul dword [ebx + 0x100]
mul dword [ebx + ecx*2]
mul word [0x100]
