from pwn import *

p = remote('node3.buuoj.cn', 26051)

p.interactive()
