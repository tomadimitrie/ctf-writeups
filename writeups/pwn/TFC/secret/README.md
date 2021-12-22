# secret

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[8]; // [rsp+0h] [rbp-30h] BYREF
  __int64 v5; // [rsp+8h] [rbp-28h]
  __int64 v6; // [rsp+10h] [rbp-20h]
  __int64 v7; // [rsp+18h] [rbp-18h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("Tell me a secret");
  *(_QWORD *)s = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  fgets(s, 32, stdin);
  if ( *(_QWORD *)s == 0xAABBCCDDAABBCCDDLL )
  {
    puts("hmm, interesting");
    system("cat flag.txt");
    putchar(10);
  }
  else
  {
    puts("I have already heard that one, sorry");
  }
  return 0;
}
```

The program reads a string from stdin and checks it against `0xaabbccddaabbccdd`. If it matches, it shows the flag. So we just need to send that byte sequence:

```python
from pwn import *

context.log_level = 'debug'

r = process("./secret")
r.clean()
r.sendline(p64(0xaabbccddaabbccdd))
r.recvline()
print(f"flag = {r.recvline().strip()}")
```

```python
[+] Starting local process './secret' argv=[b'./secret'] : pid 4080
[DEBUG] Received 0x11 bytes:
    b'Tell me a secret\n'
[DEBUG] Sent 0x9 bytes:
    00000000  dd cc bb aa  dd cc bb aa  0a                        │····│····│·│
    00000009
[DEBUG] Received 0x11 bytes:
    b'hmm, interesting\n'
[DEBUG] Received 0x6 bytes:
    b'FLAG{}'
[*] Process './secret' stopped with exit code 0 (pid 4080)
[DEBUG] Received 0x1 bytes:
    b'\n'
flag = b'FLAG{}'
```