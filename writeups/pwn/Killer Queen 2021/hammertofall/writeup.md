# Hammer to fall

## Analysis

Not really a pwn challenge, but whatever...

We have a Python script that gets an integer as input and stores
it in a numpy array. It first checks if it's -1. If it is, it exits.
It then multiplies it by 7 and adds 1 and checks again if it's equal to -1,
in which case the original number is the flag. So it's clear some kind
of integer overflow

We know that Python ints can't overflow, but what about numpy ints?
Numpy uses fixed size numeric types, so ints can overflow.

```
>>> np.iinfo(int)
iinfo(min=-9223372036854775808, max=9223372036854775807, dtype=int64)
```

So the maximum is 9223372036854775807. What happens if we input something bigger?

```
This hammer hits so hard it creates negative matter
9223372036854775809
Traceback (most recent call last):
  File "/Users/toma/Developer/ctf-writeups/writeups/pwn/Killer Queen 2021/hammertofall/hammertofall.py", line 7, in <module>
    a[0] = val
OverflowError: Python int too large to convert to C long
```

We can't store it (yet), but remember some arithmetic was applied to the number.
Let's try the maximum size:
```
This hammer hits so hard it creates negative matter
9223372036854775807
/Users/toma/Developer/ctf-writeups/writeups/pwn/Killer Queen 2021/hammertofall/hammertofall.py:8: RuntimeWarning: overflow encountered in long_scalars
  a[0] = (a[0] * 7) + 1
9223372036854775802
```
*something* happened, we got an overflow. Let's input `<max int> // 7 * 2`, which is 2635249153387078802:

```
This hammer hits so hard it creates negative matter
2635249153387078802
/Users/toma/Developer/ctf-writeups/writeups/pwn/Killer Queen 2021/hammertofall/hammertofall.py:8: RuntimeWarning: overflow encountered in long_scalars
  a[0] = (a[0] * 7) + 1
-1
flag!
```

Flag: `kqctf{2635249153387078802}`