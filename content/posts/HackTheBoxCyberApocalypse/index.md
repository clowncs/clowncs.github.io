---
weight: 1
title: "HackTheBox Cyber Apocalypse 2024"
date: 2024-03-16T14:30:00+07:00
lastmod: 2024-03-16T14:30:00+07:00
draft: false
author: "xPeters"
authorLink: "https://xpeters1337.github.io"
description: "Solutions for some reverse challenges in HTB"
tags: ["RE", "2024", "Wargame"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---
Solutions for some reverse challenges in HTB
<!--more-->

# RE
Giải này mình giải được 7 câu nhưng mình sẽ trình bày các câu medium, hard nên mọi người thông cảm. 

## FollowThePath
Thoạt đầu mới bắt đầu làm sau khi mình mở ida ra thì thấy chương trình chỉ vỏn vẹn như này

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  char v5[128]; // [rsp+40h] [rbp-98h] BYREF

  puts("Please enter the flag");
  v3 = _acrt_iob_func(0);
  common_fgets<char>(v5, 127i64, v3);
  JUMPOUT(0x140001000i64);
}
```
Mình qua đọc assembly thử:
```asm
call    j_??$common_fgets@D@@YAPEADQEADHV__crt_stdio_stream@@@Z ; common_fgets<char>(char * const,int,__crt_stdio_stream)
lea     rax, sus
mov     [rsp+0D8h+var_A0], rax
lea     rax, wrong
mov     [rsp+0D8h+var_A8], rax
lea     rax, correct
mov     [rsp+0D8h+var_B0], rax
mov     [rsp+0D8h+var_B8], rsi
mov     r10, [rsp+0D8h+var_A8]
mov     r11, [rsp+0D8h+var_B0]
mov     r12, [rsp+0D8h+var_B8]
xor     rcx, rcx
jmp     [rsp+0D8h+var_A0]
```
Sau khi nhận input người dùng nó sẽ sử dụng mảng ``sus`` để làm gì đó nếu đúng nhảy vào hàm ``correct``. Lúc này mình thực hiện đặt breakpoint và debug thử. Sau khi debug thì mình thấy như sau.

```asm
.text:00007FF71D491000 loc_7FF71D491000:                  
.text:00007FF71D491000 xor     r8, r8
.text:00007FF71D491003 mov     r8b, [r12+rcx]
.text:00007FF71D491007 xor     r8, 0C4h
.text:00007FF71D49100E cmp     r8, 8Ch
.text:00007FF71D491015 jz      loc_7FF71D49101E
.text:00007FF71D49101B jmp     r10
.text:00007FF71D49101E
.text:00007FF71D49101E loc_7FF71D49101E:                   
.text:00007FF71D49101E inc     rcx
.text:00007FF71D491021 lea     r8, loc_7FF71D491039
.text:00007FF71D491028 xor     rdx, rdx
.text:00007FF71D49102B
.text:00007FF71D49102B loc_7FF71D49102B:                   
.text:00007FF71D49102B xor     byte ptr [r8+rdx], 0DEh
.text:00007FF71D491030 inc     rdx
.text:00007FF71D491033 cmp     rdx, 39h ; '9'
.text:00007FF71D491037 jnz     short loc_7FF71D49102B
```
Nó sẽ load từng giá trị của input của mình xor với giá trị và compare với một giá trị nào đó sau đó nếu đúng nó bắt đầu xor tiếp mảng ``sus`` với giá trị bất kì và sẽ tiếp tục làm như thế. Đến đây thì mình nghĩ đây là một dạng ``self modify``. Nó tự modify chính nó để check từng kí tự, giải pháp của mình bây giờ là debug và xor ngược lại để lấy giá trị đúng sau đó set ip tới nhánh tiếp theo.

Flag: ***HTB{s3lF_d3CRYpt10N-1s_k1nd4_c00l_i5nt_1t}***

> p/s: Mình may mắn đọc được wu của anh [hitori1403](https://hitori1403.notion.site/Writeup-HTB-Cyber-Apocalypse-CTF-2024-Hacker-Royale-Reverse-945a2906689847189337982487e83815) trong câu lạc bộ và mình thấy cách này khá hay nên mạn phép share trong bài viết này luôn:

```python
import sys

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe

flag = []

def captain_hook(ql: Qiling, addr: int):
    xor_src = int.from_bytes(ql.mem.read(addr - 4, 4), "little")
    cmp_src = int.from_bytes(ql.mem.read(addr, 7)[-4:], "little")

    flag.append(cmp_src ^ xor_src)

    ql.arch.regs.r8 = cmp_src
    addr += 0x39
    ql.hook_address(captain_hook, addr, user_data=addr)

binary = ["../tools/rootfs/x8664_windows/chall.exe"]
rootfs = "/home/hitori/tools/rootfs/x8664_windows/"

ql = Qiling(binary, rootfs, verbose=QL_VERBOSE.OFF)

base_addr = ql.loader.images[0].base
cmp_inst = base_addr + 0x100E

ql.hook_address(captain_hook, cmp_inst, user_data=cmp_inst)

ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())
ql.os.stdin.write(b"a" * 0x7F)

ql.run()

print(bytes(flag))
```

## QuickScan
Bài này ta được nhận 128 file ELF và nhiệm vụ là phải gửi lại đúng giá trị mảng được load trong mỗi chương trình đấy

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/0e851518-0f68-4592-8f90-7ae747531301)

Thế thì thử decode base64 và load vào ida xem nó làm gì nhé. Sau vài lần thử thì mình rút ra được như sau dù nó thay đổi ra sao hay thêm vài thứ khác vào thì nó vẫn luôn làm câu lệnh mình note dưới đây

```asm
                 public start
LOAD:000000000804824E start:                                  ; DATA XREF: LOAD:0000000008048018↑o
LOAD:000000000804824E                 sub     rsp, 18h
LOAD:0000000008048252                 lea     rsi, byte_80482FD   // always
LOAD:0000000008048259                 mov     rdi, rsp
LOAD:000000000804825C                 mov     ecx, 18h
LOAD:0000000008048261                 rep movsb
LOAD:0000000008048263                 mov     eax, 3Ch ; '<'
LOAD:0000000008048268                 syscall                 ; LINUX - sys_exit
LOAD:000000000804826A                 mov     [rdi], ch
LOAD:000000000804826C                 scasd
LOAD:000000000804826D                 db      26h
LOAD:000000000804826D                 push    rdi
LOAD:000000000804826F                 in      eax, 3Bh
LOAD:0000000008048271                 push    rdx
LOAD:0000000008048272                 xchg    eax, ebp
LOAD:0000000008048273                 db      26h
LOAD:0000000008048273                 xor     [rdi-0Fh], esi
LOAD:0000000008048277                 nop
LOAD:0000000008048278                 adc     ah, [rax+rbp*2]
LOAD:000000000804827B                 sub     al, 0CAh
LOAD:000000000804827D                 add     eax, 0AD8E9728h
LOAD:0000000008048282                 imul    ecx, [rsp+rcx*8], 53h ; 'S'
LOAD:0000000008048286                 add     al, 9Eh
LOAD:0000000008048289                 xchg    eax, ecx
```
Thế thì lúc này phải làm sao để có thể vừa down file về vừa decode vừa lôi được mảng đó ra. Mình để ý rằng khi nó thực hiện câu lệnh nó luôn bắt đầu theo chuỗi ``[0x48, 0x83, 0xEC, 0x18, 0x48, 0x8D, 0x35]``

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/c36e83a0-d9a3-4b60-bb66-1376a8efc2d6)

Vậy thì bước đầu ta xác định được câu lệnh đó nằm ở đâu dựa theo chuỗi trên, vậy giá trị mảng sẽ nằm ở đâu. Sau khi thử nghiệm vài lần mình thấy được index của mảng sẽ bắt đầu từ vị trí tìm được chuỗi kia + 7 (tương ứng độ dài của chuỗi) + 4(độ dài của 4 bytes tiếp theo) + với giá trị của 4 bytes tiếp theo sau khi convert thành 1 byte. Script solve của mình:

```python
from pwn import *
import base64

def solve(data):
    sequence = bytes([0x48, 0x83, 0xEC, 0x18, 0x48, 0x8D, 0x35])
    index = data.find(sequence)
    four_bytes = data[index + 7 : index + 7 + 4]
    b = u32(four_bytes, sign="signed")
    s = index + 4 + 7 + b
    ans = data[s : s + 24]
    return ans.hex()

r = remote('94.237.63.93', 47097)

first = r.recvuntil("Bytes? ").decode()
print(first)
ans = first.split("Expected bytes: ")[1].split("\n")[0]
r.sendline(ans)
solved = 0
while solved < 128:
    sec = r.recvuntil("Bytes? ").decode()
    print(sec)
    elf_base64 = sec.split("ELF:  ")[1].split("\n")[0]
    elf = base64.b64decode(elf_base64)
    answer = solve(elf)
    print(answer)
    r.sendline(answer)
    solved += 1
flag = r.recv().decode()
print(flag)
```
Flag: ***HTB{y0u_4n4lyz3d_th3_p4tt3ns!}***

## METAGAMING
Bài này cho sẵn source code C++ tuy nhiên mình thấy nó rất là ..., chỉ tưởng tượng nó được compile xong thì không biết sẽ như thế nào. Đọc sơ chương trình, đây là phần mình thấy ấn tượng nhất.

```C
template<flag_t Flag, insn_t... Instructions>
struct program_t {
    using R = std::array<uint32_t, 15>;

    template<insn_t Insn>
    static constexpr void execute_one(R &regs) {
        if constexpr (Insn.opcode == 0) {
            regs[Insn.op0] = Flag.at(Insn.op1);
        } else if constexpr (Insn.opcode == 1) {
            regs[Insn.op0] = Insn.op1;
        } else if constexpr (Insn.opcode == 2) {
            regs[Insn.op0] ^= Insn.op1;
        } else if constexpr (Insn.opcode == 3) {
            regs[Insn.op0] ^= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 4) {
            regs[Insn.op0] |= Insn.op1;
        } else if constexpr (Insn.opcode == 5) {
            regs[Insn.op0] |= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 6) {
            regs[Insn.op0] &= Insn.op1;
        } else if constexpr (Insn.opcode == 7) {
            regs[Insn.op0] &= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 8) {
            regs[Insn.op0] += Insn.op1;
        } else if constexpr (Insn.opcode == 9) {
            regs[Insn.op0] += regs[Insn.op1];
        } else if constexpr (Insn.opcode == 10) {
            regs[Insn.op0] -= Insn.op1;
        } else if constexpr (Insn.opcode == 11) {
            regs[Insn.op0] -= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 12) {
            regs[Insn.op0] *= Insn.op1;
        } else if constexpr (Insn.opcode == 13) {
            regs[Insn.op0] *= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 14) {
            __noop;
        } else if constexpr (Insn.opcode == 15) {
            __noop;
            __noop;
        } else if constexpr (Insn.opcode == 16) {
            regs[Insn.op0] = rotr(regs[Insn.op0], Insn.op1);
        } else if constexpr (Insn.opcode == 17) {
            regs[Insn.op0] = rotr(regs[Insn.op0], regs[Insn.op1]);
        } else if constexpr (Insn.opcode == 18) {
            regs[Insn.op0] = rotl(regs[Insn.op0], Insn.op1);
        } else if constexpr (Insn.opcode == 19) {
            regs[Insn.op0] = rotl(regs[Insn.op0], regs[Insn.op1]);
        } else if constexpr (Insn.opcode == 20) {
            regs[Insn.op0] = regs[Insn.op1];
        } else if constexpr (Insn.opcode == 21) {
            regs[Insn.op0] = 0;
        } else if constexpr (Insn.opcode == 22) {
            regs[Insn.op0] >>= Insn.op1;
        } else if constexpr (Insn.opcode == 23) {
            regs[Insn.op0] >>= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 24) {
            regs[Insn.op0] <<= Insn.op1;
        } else if constexpr (Insn.opcode == 25) {
            regs[Insn.op0] <<= regs[Insn.op1];
        } else {
            static_assert(always_false_insn_v<Insn>);
        }
    }

```
Nhìn khá giống dạng VM vì thường các dạng VM sẽ dựa theo opcode để thực hiện các instructions. Đây là code mình viết để xem nó hoạt động ra sao dựa trên đoạn chương trình chính
```C
using program = program_t<flag, insn_t(12, 13, 10), insn_t(21, 0, 0), insn_t(0, 13, 13), insn_t(0, 14, 0), insn_t(15, 11, 12), insn_t(24, 14, 0), insn_t(5, 0, 14), insn_t(0, 14, 1), insn_t(7, 11, 11), insn_t(24, 14, 8), insn_t(5, 0, 14), insn_t(0, 14, 2), insn_t(2, 10, 11), insn_t(24, 14, 16), insn_t(18, 12, 11), insn_t(5, 0, 14), insn_t(0, 14, 3),...
```

```python
byte = [12, 13, 10, 21, 0, 0, 0, 13, 13, 0, 14, 0, 15, 11, ... 3, 9, 10]

for i in range(0, len(byte), 3):
    opcode = byte[i]
    op0 = byte[i+1]
    op1 = byte[i+2]
    if opcode == 14 or opcode == 15:
        print("")
    match opcode:
        case 0:
            print(f"regs[{op0}] = flag[{op1}]")
        case 1:
            print(f"regs[{op0}] = {op1}")
        case 2:
            print(f"regs[{op0}] ^= {op1}")
        case 3:
             print(f"regs[{op0}] ^= regs[{op1}]")
        case 4:
             print(f"regs[{op0}] |= {op1}")
        case 5:
            print(f"regs[{op0}] |= regs[{op1}]")
        case 6:
            print(f"regs[{op0}] &= {op1}")
        case 7:
            print(f"regs[{op0}] &= regs[{op1}]")
        case 8:
            print(f"regs[{op0}] += {op1}")
        case 9:
            print(f"regs[{op0}] += regs[{op1}]")
        case 10:
            print(f"regs[{op0}] -= {op1}")
        case 11:
            print(f"regs[{op0}] -= regs[{op1}]")
        case 12:
            print(f"regs[{op0}] *= {op1}")
        case 13:
            print(f"regs[{op0}] *= regs[{op1}]")
        case 16:
            print(f"regs[{op0}] = ror(regs[{op0}], {op1})")
        case 17:
            print(f"regs[{op0}] = ror(regs[{op0}], regs[{op1}])")
        case 18:
            print(f"regs[{op0}] = rol(regs[{op0}], {op1})")
        case 19:
            print(f"regs[{op0}] = rol(regs[{op0}], regs[{op1}])")
        case 20:
            print(f"regs[{op0}] = regs[{op1}]")
        case 21:
            print(f"regs[{op0}] = 0")
        case 22:
            print(f"regs[{op0}] >>= {op1}")
        case 23:
            print(f"regs[{op0}] >>= regs[{op1}]")
        case 24:
            print(f"regs[{op0}] <<= {op1}")
        case 25:
            print(f"regs[{op0}] <<= regs[{op1}]")
```

Với dạng VM viết được disassembler là dường như đã nắm trong tay được 70%, phần còn lại là hiểu nó làm gì và viết được script giải. Ngó lại với điều kiện cần để flag đúng.

```C
 static_assert(program::registers[0] == 0x3ee88722 && program::registers[1] == 0xecbdbe2 && program::registers[2] == 0x60b843c4 && program::registers[3] == 0x5da67c7 && program::registers[4] == 0x171ef1e9 && program::registers[5] == 0x52d5b3f7 && program::registers[6] == 0x3ae718c0 && program::registers[7] == 0x8b4aacc2 && program::registers[8] == 0xe5cf78dd && program::registers[9] == 0x4a848edf && program::registers[10] == 0x8f && program::registers[11] == 0x4180000 && program::registers[12] == 0x0 && program::registers[13] == 0xd && program::registers[14] == 0x0, "Ah! Your flag is invalid.");
```

Nó chia thành 15 register và từng register đạt giá trị tương ứng thì flag đúng thế thì tới đây với disassmbler ta có thể dịch ngược và tìm đúng được thứ mình cần. Flag được chia mỗi phần làm 4 và được packed từ regs[0] -> regs[9]. Sau khi đọc thử thì mình phát hiện đây là khúc quan trọng của mỗi thanh ghi.

```
regs[9] -= 532704100
regs[9] -= 2519542932
regs[9] ^= 2451309277
regs[9] ^= 3957445476
regs[10] |= regs[10]
regs[9] += 2583554449
regs[9] -= 1149665327
regs[13] *= 12
regs[9] += 3053959226
regs[10] = flag[10]
regs[9] += 3693780276

regs[9] ^= 609918789
regs[9] ^= 2778221635
regs[13] = ror(regs[13], 10)
regs[9] += 3133754553
regs[11] += 13
regs[9] += 3961507338
regs[9] ^= 1829237263
regs[11] = ror(regs[11], 13)
regs[9] ^= 2472519933
regs[12] &= 12
regs[9] += 4061630846
regs[9] -= 1181684786
regs[10] *= regs[11]
regs[9] -= 390349075
regs[9] += 2883917626
regs[9] -= 3733394420
regs[12] -= 12
regs[9] ^= 3895283827
regs[10] = regs[11]
regs[9] ^= 2257053750
regs[9] -= 2770821931
regs[10] = rol(regs[10], 13)
regs[9] ^= 477834410
regs[9] ^= regs[10]
```
Các thanh ghi từ 0 -> 9 đều thực hiện những phép tính toán bất kì. Việc bạn cần làm là xác định lúc nó bắt đầu đó là lúc nó bắt đầu thao tác với các hằng số và đảo ngược lại phép tính. Đây là của regs[9]. 

```C
#include <stdio.h>
#include <stdint.h>
int main(){
    unsigned char flag[4];
    uint32_t reg = 0x4a848edf;
    reg ^= 0x8f;
    reg ^= 477834410;
    reg += 2770821931;
    reg ^= 2257053750;
    reg ^= 3895283827;
    reg += 3733394420;
    reg -= 2883917626;
    reg += 390349075;
    reg += 1181684786;
    reg -= 4061630846;
    reg ^= 2472519933;
    reg ^= 1829237263;
    reg -= 3961507338;
    reg -= 3133754553;
    reg ^= 2778221635;
    reg ^= 609918789;
    reg -= 3693780276;
    reg -= 3053959226;
    reg += 1149665327;
    reg -= 2583554449;
    reg ^= 3957445476;
    reg ^= 2451309277;
    reg += 2519542932;
    reg += 532704100;
    flag[0] = (reg >> 0) & 0xFF;
    flag[1] = (reg >> 8) & 0xFF;
    flag[2] = (reg >> 16) & 0xFF;
    flag[3] = (reg >> 24) & 0xFF;
    puts(flag);
}
```
Tương tự với regs[8] -> regs[0]:

Flag: ***HTB{m4n_1_l0v4_cXX_TeMpl4t35_9fb60c17b0}***

> Thanks for reading!

