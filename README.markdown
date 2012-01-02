The Binary Introspection Toolkit
============================

Introduction
------------
The goal of the binary introspection toolkit (BIT) is to create a collection of **static** & **dynamic** analysis tools to analyze *(malicious)* binaries.

Roadmap
-------
The first release is focused on creating an intermediate language for static analysis purposes.
The intermediate language implented is based on [**REIL**][1], an architecture independent intermediate language for binaries focused on reverse engineering. 

[1]: http://www.zynamics.com/downloads/csw09.pdf "REIL"

Example
-------
The following output is the translation of object code from tests/add.asm

	0x00000000 ADD T0/4, T3/4, T256/8                   // add eax,ebx
	0x00000001 STR T256/4, , T0/4                       // add eax,ebx

	0x00000200 LDM T0/4, , T256/4                       // add [eax],ebx
	0x00000201 ADD T256/4, T3/4, T257/8                 // add [eax],ebx
	0x00000202 STM T257/4, , T0/4                       // add [eax],ebx

	0x00000400 ADD T0/4, 0x100/4, T256/8                // add [eax+0x100],ebx
	0x00000401 LDM T256/4, , T257/4                     // add [eax+0x100],ebx
	0x00000402 ADD T257/4, T3/4, T258/8                 // add [eax+0x100],ebx
	0x00000403 STM T258/4, , T256/4                     // add [eax+0x100],ebx

	0x00000a00 LDM T3/4, , T256/4                       // add eax,[ebx]
	0x00000a01 ADD T0/4, T256/4, T257/8                 // add eax,[ebx]
	0x00000a02 STR T257/4, , T0/4                       // add eax,[ebx]

	0x00000c00 MUL T3/4, 0x2/4, T256/8                  // add [eax+ebx*2],ecx
	0x00000c01 ADD T0/4, T256/4, T257/8                 // add [eax+ebx*2],ecx
	0x00000c02 LDM T257/4, , T258/4                     // add [eax+ebx*2],ecx
	0x00000c03 ADD T258/4, T1/4, T259/8                 // add [eax+ebx*2],ecx
	0x00000c04 STM T259/4, , T257/4                     // add [eax+ebx*2],ecx
