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

#ifndef _EXAMPLES64FREEBSD_H_
#define _EXAMPLES64FREEBSD_H_

const char shellcode_64bits_freebsd[] =
        "\x48\x31\xc0"                               // xor    %rax,%rax
        "\x99"                                       // cltd
        "\xb0\x3b"                                   // mov    $0x3b,%al
        "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68"   // mov $0x68732f6e69622fff,%rdi
        "\x48\xc1\xef\x08"                           // shr    $0x8,%rdi
        "\x57"                                       // push   %rdi
        "\x48\x89\xe7"                               // mov    %rsp,%rdi
        "\x57"                                       // push   %rdi
        "\x52"                                       // push   %rdx
        "\x48\x89\xe6"                               // mov    %rsp,%rsi
        "\x0f\x05";                                  // syscall


#endif
