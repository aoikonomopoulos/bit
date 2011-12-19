# Test cases for the SUB instruction
BITS 32

sub eax,ebx
sub dword [eax], ebx
sub dword [eax + 0x100], ebx
sub eax, [ebx]
sub dword [eax + ebx*2], ecx

sub ax,bx
