# AGoodOne (rev)

# Challenge description

One would simply want to be with the rest.

NOTE: The format of the flag is CTF{}, for example: CTF{foobar}. The flag must be submitted in full, including the CTF and curly bracket parts.

# Flag proof:

> CTF{fc3a41a577ff10786a2fdbfcad18e47e78d426a47d097a49e803f7ec0e6}
> 

# Summary:

The binary contains an algorithm that shows if the password gave as command line argument is correct (similar to Combined). Apparently the password wasn't the flag, and we needed to use that password to decrypt the encrypted flag in the binary

# Details:

Let's open the binary in IDA and we see two functions:

- main

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int v5; // eax
  size_t len; // [rsp+18h] [rbp-8h]

  v3 = time(0LL);
  srand(v3);
  if ( argc > 1 )
  {
    len = (int)strlen(argv[1]);
    if ( check_password((char *)argv[1], len) )
    {
      puts(s);
      return 0;
    }
    else
    {
      v5 = rand();
      printf("%s", &fail_msgs[64 * (__int64)(v5 % 14)]);
      return -1;
    }
  }
  else
  {
    printf("Usage: %s <key_value>\n", *argv);
    return -1;
  }
}
```

- check_password

```c
bool __fastcall check_password(char *passwd, size_t len)
{
  int v2; // ebx
  unsigned int result; // [rsp+18h] [rbp-18h]
  int i; // [rsp+1Ch] [rbp-14h]

  result = 0;
  for ( i = 0; len > i; ++i )
  {
    v2 = len ^ passwd[i];
    result |= v2 ^ strlen(enc_flag);
    printf("%d", result);
  }
  printf("%d\n", result);
  return result == 0;
}
```

We also see the encrypted flag:

```c
.data:00000000000043E0 enc_flag        dq offset unk_2008

.rodata:0000000000002008 unk_2008        db    6                 ; DATA XREF: .data:enc_flag↓o
.rodata:0000000000002009                 db  11h
.rodata:000000000000200A                 db    3
.rodata:000000000000200B                 db  3Eh ; >
.rodata:000000000000200C                 db  23h ; #
.rodata:000000000000200D                 db  26h ; &
.rodata:000000000000200E                 db  76h ; v
.rodata:000000000000200F                 db  24h ; $
.rodata:0000000000002010                 db  71h ; q
.rodata:0000000000002011                 db  74h ; t
.rodata:0000000000002012                 db  24h ; $
.rodata:0000000000002013                 db  70h ; p
.rodata:0000000000002014                 db  72h ; r
.rodata:0000000000002015                 db  72h ; r
.rodata:0000000000002016                 db  23h ; #
.rodata:0000000000002017                 db  23h ; #
.rodata:0000000000002018                 db  74h ; t
.rodata:0000000000002019                 db  75h ; u
.rodata:000000000000201A                 db  72h ; r
.rodata:000000000000201B                 db  7Dh ; }
.rodata:000000000000201C                 db  73h ; s
.rodata:000000000000201D                 db  24h ; $
.rodata:000000000000201E                 db  77h ; w
.rodata:000000000000201F                 db  23h ; #
.rodata:0000000000002020                 db  21h ; !
.rodata:0000000000002021                 db  27h ; '
.rodata:0000000000002022                 db  23h ; #
.rodata:0000000000002023                 db  26h ; &
.rodata:0000000000002024                 db  24h ; $
.rodata:0000000000002025                 db  21h ; !
.rodata:0000000000002026                 db  74h ; t
.rodata:0000000000002027                 db  7Dh ; }
.rodata:0000000000002028                 db  20h
.rodata:0000000000002029                 db  23h ; #
.rodata:000000000000202A                 db  71h ; q
.rodata:000000000000202B                 db  72h ; r
.rodata:000000000000202C                 db  20h
.rodata:000000000000202D                 db  24h ; $
.rodata:000000000000202E                 db  72h ; r
.rodata:000000000000202F                 db  7Dh ; }
.rodata:0000000000002030                 db  21h ; !
.rodata:0000000000002031                 db  71h ; q
.rodata:0000000000002032                 db  77h ; w
.rodata:0000000000002033                 db  73h ; s
.rodata:0000000000002034                 db  24h ; $
.rodata:0000000000002035                 db  71h ; q
.rodata:0000000000002036                 db  72h ; r
.rodata:0000000000002037                 db  21h ; !
.rodata:0000000000002038                 db  75h ; u
.rodata:0000000000002039                 db  7Ch ; |
.rodata:000000000000203A                 db  72h ; r
.rodata:000000000000203B                 db  24h ; $
.rodata:000000000000203C                 db  71h ; q
.rodata:000000000000203D                 db  7Ch ; |
.rodata:000000000000203E                 db  20h
.rodata:000000000000203F                 db  76h ; v
.rodata:0000000000002040                 db  7Dh ; }
.rodata:0000000000002041                 db  75h ; u
.rodata:0000000000002042                 db  76h ; v
.rodata:0000000000002043                 db  23h ; #
.rodata:0000000000002044                 db  72h ; r
.rodata:0000000000002045                 db  20h
.rodata:0000000000002046                 db  7Ch ; |
.rodata:0000000000002047                 db  26h ; &
.rodata:0000000000002048                 db  75h ; u
.rodata:0000000000002049                 db  20h
.rodata:000000000000204A                 db  7Ch ; |
.rodata:000000000000204B                 db  73h ; s
.rodata:000000000000204C                 db  38h ; 8
.rodata:000000000000204D                 db    0
```

The algorithm looks like this in python (where 69 is the length of `enc_flag`):

```python
s = input()
result = 0
for c in s:
    result |= len(s) ^ ord(c) ^ 69
print(result)
```

And we need that `result` to be 0. I identified the empty string to be a good candidate, but it wasn't useful. After some trial and error (and referring to the title) I came to the conclusion that the string needs to be 1 character long. So I bruteforced it:

```python
for c in range(0xff):
    result = 0 | (c ^ 1 ^ 69)
    if result == 0:
        print(c)
```

The output is 68 (or "D"). We have the password, now let's decrypt the flag. I tried xor-ing the bytes with 68 but it didn't decrypt properly, so I referred once again to the title and xor-ed them again with 1

```python
s = b"\x06\x11\x03\x3E\x23\x26\x76\x24\x71\x74\x24\x70\x72\x72\x23\x23\x74\x75\x72\x7D\x73\x24\x77\x23\x21\x27\x23\x26\x24\x21\x74\x7D\x20\x71\x72\x20\x72\x7D\x21\x71\x77\x73\x24\x71\x72\x21\x75\x7C\x72\x24\x71\x7C\x20\x7D\x75\x76\x23\x72\x20\x26\x75\x20\x73\x38"
for i in s:
    print(chr(i ^ 68 ^ 1), end="")
```

```python
CTF{fc3a41a577ff10786a2fdbfcad18e47e78d426a47d097a49e803f7ec0e6}
```