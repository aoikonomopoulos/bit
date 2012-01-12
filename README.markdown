The Binary Introspection Toolkit
============================

Introduction
------------
The goal of the binary introspection toolkit (BIT) is to create a collection of **static** & **dynamic** analysis tools to analyze *(malicious)* binaries.

Roadmap
-------
The first release is focused on creating an intermediate language for static analysis purposes.
The intermediate language implemented is based on [**REIL**][1], an architecture independent intermediate language for binaries focused on reverse engineering. 

[1]: http://www.zynamics.com/downloads/csw09.pdf "REIL"

Example
-------
The following output is part of the translation of object code from tests/arithmetic.asm:
   0x00000000 ADD eax, 0x100, qword T104               // add eax,0x100
   0x00000001 AND qword T104, 0xffffffff, dword T105  
   0x00000002 RSH dword T105, 0xf, dword T106         
   0x00000003 AND dword T106, 0xff, byte T107         
   0x00000004 STR byte T107, , cf                     
   0x00000005 AND dword T105, 0xff, byte T108         
   0x00000006 RSH byte T108, 0x4, byte T109           
   0x00000007 XOR byte T108, byte T109, byte T110     
   0x00000008 AND byte T110, 0xf, byte T111           
   0x00000009 STR 0x6996, , word T112                 
   0x0000000a RSH word T112, byte T111, word T113     
   0x0000000b AND word T113, 0x1, word T114           
   0x0000000c AND word T114, 0xff, byte T115          
   0x0000000d STR byte T115, , pf                     
   0x0000000e BISZ dword T105, , zf                   
   0x0000000f RSH dword T105, 0x1f, dword T116        
   0x00000010 AND dword T116, 0xff, byte T117         
   0x00000011 STR byte T117, , sf                     
   0x00000012 XOR eax, 0x100, dword T118              
   0x00000013 XOR dword T118, 0xffffffff, dword T119  
   0x00000014 XOR eax, dword T105, dword T120         
   0x00000015 AND dword T119, dword T120, dword T121  
   0x00000016 RSH dword T121, 0x1f, dword T122        
   0x00000017 AND dword T122, 0xff, byte T123         
   0x00000018 STR byte T123, , of                     
   0x00000019 STR dword T105, , eax                   
