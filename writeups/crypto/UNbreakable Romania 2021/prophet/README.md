# prophet (crypto)

# Challenge description:

The prophecy may take time.

Flag format: CTF{(sha256sum)}

# Flag proof:

> CTF{441cc012bcb1802a300c2767271a9297613e5cd037496479da7d24b2251dd4a6}
> 

# Summary:

We can use the Padding oracle attack in order to get the flag

# Details:

Let's connect to the server:

```bash
Welcome to my private conversations. All messages are encrypted with a key only known by me and Bob.
1. Receive message
2. Send message
Option:
```

If we select 1, we get an encrypted message:

```bash
Option: 1
Msg: dm6k9fAzP8Cbaj28xghUYMyIepXEqewrYgQVT30DRGo1BqDidqwK8JtemJDDRaAh+WxrYhu3vgGqaSJpJ0WScQXOtemLPs7pIhh/fOs/Njoly0ur8gae5+8JVMJwmJzm
```

If we run 1 again, we get the same string. But if we connect to the server again, we get a different one. Let's try to use the second option:

```bash
Welcome to my private conversations. All messages are encrypted with a key only known by me and Bob.
1. Receive message
2. Send message
Option: 2
Msg:
Traceback (most recent call last):
  File "/home/ctf/server.py", line 70, in <module>
    menu()
  File "/home/ctf/server.py", line 61, in menu
    if is_padding_ok(cipher):
  File "/home/ctf/server.py", line 44, in is_padding_ok
    return _decrypt(data) is True
  File "/home/ctf/server.py", line 35, in _decrypt
    cipher = AES.new(_key, AES.MODE_CBC, iv)
  File "/usr/local/lib/python3.9/dist-packages/Crypto/Cipher/AES.py", line 232, in new
    return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)
  File "/usr/local/lib/python3.9/dist-packages/Crypto/Cipher/__init__.py", line 79, in _create_cipher
    return modes[mode](factory, **kwargs)
  File "/usr/local/lib/python3.9/dist-packages/Crypto/Cipher/_mode_cbc.py", line 287, in _create_cbc_cipher
    raise ValueError("Incorrect IV length (it must be %d bytes long)" %
ValueError: Incorrect IV length (it must be 16 bytes long)
➜  Desktop nc 34.159.235.104 31907

Welcome to my private conversations. All messages are encrypted with a key only known by me and Bob.
1. Receive message
2. Send message
Option: 2
Msg:A
Traceback (most recent call last):
  File "/home/ctf/server.py", line 70, in <module>
    menu()
  File "/home/ctf/server.py", line 61, in menu
    if is_padding_ok(cipher):
  File "/home/ctf/server.py", line 44, in is_padding_ok
    return _decrypt(data) is True
  File "/home/ctf/server.py", line 33, in _decrypt
    data = base64.b64decode(data)
  File "/usr/lib/python3.9/base64.py", line 87, in b64decode
    return binascii.a2b_base64(s)
binascii.Error: Invalid base64-encoded string: number of data characters (1) cannot be 1 more than a multiple of 4
➜  Desktop nc 34.159.235.104 31907

Welcome to my private conversations. All messages are encrypted with a key only known by me and Bob.
1. Receive message
2. Send message
Option: 2
Msg:adslijahdhkbhdbjdasbkadsasd
Traceback (most recent call last):
  File "/home/ctf/server.py", line 70, in <module>
    menu()
  File "/home/ctf/server.py", line 61, in menu
    if is_padding_ok(cipher):
  File "/home/ctf/server.py", line 44, in is_padding_ok
    return _decrypt(data) is True
  File "/home/ctf/server.py", line 33, in _decrypt
    data = base64.b64decode(data)
  File "/usr/lib/python3.9/base64.py", line 87, in b64decode
    return binascii.a2b_base64(s)
binascii.Error: Incorrect padding
➜  Desktop nc 34.159.235.104 31907

Welcome to my private conversations. All messages are encrypted with a key only known by me and Bob.
1. Receive message
2. Send message
Option: 1
Msg: HYCmMXW2o+Pwrx2TDLcemlv9Nmj9wOddd+Xr0i3OWLjtW5/GPJo80suOZPhMHC6P30x4Ly+CHkBw67YtJn6a6fhRNKWm2wUTQFXhq5ihzYfQ36EWThF/+XtVGwTSLJDI

1. Receive message
2. Send message
Option: 2
Msg:HYCmMXW2o+Pwrx2TDLcemlv9Nmj9wOddd+Xr0i3OWLjtW5/GPJo80suOZPhMHC6P30x4Ly+CHkBw67YtJn6a6fhRNKWm2wUTQFXhq5ihzYfQ36EWThF/+XtVGwTSLJDI
Ack.

➜  Desktop nc 34.159.235.104 31907

Welcome to my private conversations. All messages are encrypted with a key only known by me and Bob.
1. Receive message
2. Send message
Option: 2
Msg:dm6k9fAzP8Cbaj28xghUYMyIepXEqewrYgQVT30DRGo1BqDidqwK8JtemJDDRaAh+WxrYhu3vgGqaSJpJ0WScQXOtemLPs7pIhh/fOs/Njoly0ur8gae5+8JVMJwmJzm
Padding seems invalid

1. Receive message
2. Send message
Option:
```

Here we learn multiple things:

- the server uses the CBC mode for AES (as the traceback shows)
- sending a random message throws an `Incorrect padding` error
- sending the same message that we received returns an `Ack.`
- sending a message received in a previous session returns `padding seems invalid` **but does not close the connection**

I did some research on the CBC encryption and found the padding oracle attack ([https://en.wikipedia.org/wiki/Padding_oracle_attack](https://en.wikipedia.org/wiki/Padding_oracle_attack)) which somehow relates to the title of the challenge. I found a Python module for it named `padding_oracle`

```bash
from padding_oracle import padding_oracle, base64_encode
from pwn import *
import logging

context.log_level = 'debug'

s = remote("34.159.235.104", 31907)

def runner(cipher: bytes):
    s.clean()
    s.sendline(b"2")
    s.clean()
    s.sendline(base64_encode(cipher))
    error = s.clean()
    if b"Incorrect padding" in error:
        exit()
    return b'seems invalid' not in error

s.recv(1024)
s.sendline(b"1")
msg = s.clean().split()[1]
log.success(f"{msg=}")

print(base64_encode(padding_oracle(msg, 16, runner)))
```

First I tried using the `socket` module but sometimes it read the data incorrectly, so I used `pwntools`. I also modified the library a bit, because it used thread pools and I/O to the same connection from different threads would be bad

After running the script and decoding, we get the flag