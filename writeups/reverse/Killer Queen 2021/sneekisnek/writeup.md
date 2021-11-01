# Sneekisnek

## Analysis

We are provided with some Python bytecode in readable form. We can find a decompiler
(I didn't find any that worked good with readable bytecode) or we can analyze it ourselves.

[Here](https://docs.python.org/3/library/dis.html) is the Python documentation about the instructions.

[Here](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d) is a good article about the bytecode instructions.

```
 4           0 LOAD_CONST               1 ('')
              2 STORE_FAST               0 (f)

  5           4 LOAD_CONST               2 ('rwhxi}eomr\\^`Y')
              6 STORE_FAST               1 (a)

  6           8 LOAD_CONST               3 ('f]XdThbQd^TYL&\x13g')
             10 STORE_FAST               2 (z)

  7          12 LOAD_FAST                1 (a)
             14 LOAD_FAST                2 (z)
             16 BINARY_ADD
             18 STORE_FAST               1 (a)
```

```py
f = ''
a = 'rwhxi}eomr\\^`Y'
z = 'f]XdThbQd^TYL&\x13g'
a += z
```

---

```
  8          20 LOAD_GLOBAL              0 (enumerate)
             22 LOAD_FAST                1 (a)
             24 CALL_FUNCTION            1
             26 GET_ITER
        >>   28 FOR_ITER                48 (to 78) 
             30 UNPACK_SEQUENCE          2
             32 STORE_FAST               3 (i)
             34 STORE_FAST               4 (b)
```

```py
for i, b in enumerate(a):
    # ...
```

---

```
  9          36 LOAD_GLOBAL              1 (ord)
             38 LOAD_FAST                4 (b)
             40 CALL_FUNCTION            1
             42 STORE_FAST               5 (c)
```

```py
c = ord(b)
```

---

```
 10          44 LOAD_FAST                5 (c)
             46 LOAD_CONST               4 (7)
             48 BINARY_SUBTRACT
             50 STORE_FAST               5 (c)
```

```py
c -= 7
```

---

```
 11          52 LOAD_FAST                5 (c)
             54 LOAD_FAST                3 (i)
             56 BINARY_ADD
             58 STORE_FAST               5 (c)
```

```py
c += i
```

---

```
 12          60 LOAD_GLOBAL              2 (chr)
             62 LOAD_FAST                5 (c)
             64 CALL_FUNCTION            1
             66 STORE_FAST               5 (c)
```


```py
c = chr(c)
```

---

```
 13          68 LOAD_FAST                0 (f)
             70 LOAD_FAST                5 (c)
             72 INPLACE_ADD
             74 STORE_FAST               0 (f)
             76 JUMP_ABSOLUTE           28
```

```py
f += c

# loop again...
```

---

```

 14     >>   78 LOAD_GLOBAL              3 (print)
             80 LOAD_FAST                0 (f)
             82 CALL_FUNCTION            1
             84 POP_TOP
             86 LOAD_CONST               0 (None)
             88 RETURN_VALUE
```

```py
print(f)
```

---

Final script:

```py
f = ''
a = 'rwhxi}eomr\\^`Y'
z = 'f]XdThbQd^TYL&\x13g'
a += z

for i, b in enumerate(a):
    c = ord(b)
    c -= 7
    c += i
    c = chr(c)
    f += c

print(f)
```

Flag: `kqctf{dont_be_mean_to_snek_:(}`